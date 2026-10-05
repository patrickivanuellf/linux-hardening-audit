from __future__ import annotations

import configparser
import os
import re
import shutil
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, Optional, Tuple

PASS, WARN, FAIL, SKIP = "PASS", "WARN", "FAIL", "SKIP"
WEIGHTS = {"high": 3, "medium": 2, "low": 1}


@dataclass
class Result:
    id: str
    category: str
    title: str
    status: str
    detail: str = ""
    fix: str = ""
    severity: str = "medium"


class Context:
    """Where checks read from.

    root="/" audits the live host. Any other directory is treated as an
    offline filesystem tree (for example an extracted container image), in
    which case checks that need a running system are skipped.
    """

    def __init__(self, root="/"):
        self.root = Path(root).resolve()
        self.live = self.root == Path("/")

    def path(self, p: str) -> Path:
        return self.root / p.lstrip("/")

    def read(self, p: str) -> Optional[str]:
        try:
            return self.path(p).read_text(errors="replace")
        except OSError:
            return None

    def exists(self, p: str) -> bool:
        return self.path(p).exists()

    def glob(self, directory: str, pattern: str) -> List[Path]:
        d = self.path(directory)
        return sorted(d.glob(pattern)) if d.is_dir() else []

    def run(self, cmd: List[str]) -> Optional[str]:
        if not self.live or shutil.which(cmd[0]) is None:
            return None
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=10, check=False
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        return proc.stdout


# --------------------------------------------------------------------- SSH

_KV = re.compile(r"^(\S+?)(?:\s*=\s*|\s+)(.*)$")


def parse_sshd(ctx: Context) -> Optional[dict]:
    """Return the global sshd settings as {keyword: value}.

    Like sshd, the first value for a keyword wins. Drop-in files in
    sshd_config.d are read before the main file (Debian/Ubuntu put the
    Include line at the top). Match blocks are ignored.
    """
    sources = ctx.glob("/etc/ssh/sshd_config.d", "*.conf")
    main = ctx.path("/etc/ssh/sshd_config")
    if main.exists():
        sources.append(main)
    if not sources:
        return None
    values: dict = {}
    for src in sources:
        try:
            text = src.read_text(errors="replace")
        except OSError:
            continue
        for raw in text.splitlines():
            line = raw.split("#", 1)[0].strip()
            m = _KV.match(line)
            if not m:
                continue
            key, val = m.group(1).lower(), m.group(2).strip().strip('"').lower()
            if key == "match":
                break
            if key == "include":
                continue
            values.setdefault(key, val)
    return values


def _must_be(wanted: str, unset_status: str, unset_detail: str):
    def evaluate(v: Optional[str]) -> Tuple[str, str]:
        if v is None:
            return unset_status, unset_detail
        return (PASS if v == wanted else FAIL), f"set to '{v}'"

    return evaluate


def _root_login(v: Optional[str]) -> Tuple[str, str]:
    if v is None:
        return WARN, "not set; the default depends on the OpenSSH version"
    if v == "no":
        return PASS, "set to 'no'"
    if v in ("prohibit-password", "without-password"):
        return WARN, f"set to '{v}' (root can still log in with a key)"
    return FAIL, f"set to '{v}'"


def _max_auth_tries(v: Optional[str]) -> Tuple[str, str]:
    if v is None:
        return WARN, "not set; OpenSSH defaults to 6"
    try:
        n = int(v)
    except ValueError:
        return WARN, f"unreadable value '{v}'"
    return (PASS if n <= 4 else WARN), f"set to {n}"


SSH_RULES = [
    ("SSH-001", "permitrootlogin", "Root login over SSH is disabled", "high",
     _root_login, "Set 'PermitRootLogin no' in /etc/ssh/sshd_config and reload sshd."),
    ("SSH-002", "passwordauthentication", "SSH password authentication is disabled", "high",
     _must_be("no", FAIL, "not set; OpenSSH defaults to 'yes'"),
     "Use key-based login, then set 'PasswordAuthentication no' and reload sshd."),
    ("SSH-003", "permitemptypasswords", "Empty passwords are rejected over SSH", "high",
     _must_be("no", PASS, "not set; OpenSSH defaults to 'no'"),
     "Set 'PermitEmptyPasswords no'."),
    ("SSH-004", "maxauthtries", "SSH limits authentication attempts (MaxAuthTries <= 4)", "medium",
     _max_auth_tries, "Set 'MaxAuthTries 3' (or 4)."),
    ("SSH-005", "x11forwarding", "X11 forwarding is disabled", "low",
     _must_be("no", PASS, "not set; OpenSSH defaults to 'no'"),
     "Set 'X11Forwarding no' unless you need it."),
    ("SSH-006", "permituserenvironment", "Users cannot pass environment variables over SSH", "medium",
     _must_be("no", PASS, "not set; OpenSSH defaults to 'no'"),
     "Set 'PermitUserEnvironment no'."),
]


def check_ssh(ctx: Context) -> List[Result]:
    cfg = parse_sshd(ctx)
    results = []
    for rid, key, title, sev, evaluate, fix in SSH_RULES:
        if cfg is None:
            results.append(Result(rid, "SSH", title, SKIP,
                                  "sshd_config not found (SSH server not installed?)", fix, sev))
            continue
        status, detail = evaluate(cfg.get(key))
        results.append(Result(rid, "SSH", title, status, detail, fix, sev))
    return results


# ---------------------------------------------------------------- firewall

def check_firewall(ctx: Context) -> Result:
    title = "Host firewall (ufw) is enabled"
    fix = ("sudo ufw default deny incoming && sudo ufw allow OpenSSH && "
           "sudo ufw enable")
    conf = ctx.read("/etc/ufw/ufw.conf")
    if conf is None:
        return Result("FW-001", "Firewall", title, WARN,
                      "ufw is not installed; make sure another firewall "
                      "(nftables, iptables or a cloud firewall) is in place",
                      fix, "high")
    enabled = any(re.match(r"\s*ENABLED\s*=\s*yes\b", ln, re.I)
                  for ln in conf.splitlines())
    if enabled:
        return Result("FW-001", "Firewall", title, PASS, "ENABLED=yes", fix, "high")
    return Result("FW-001", "Firewall", title, FAIL,
                  "ufw is installed but ENABLED is not 'yes'", fix, "high")


# ---------------------------------------------------------------- fail2ban

def check_fail2ban(ctx: Context) -> Result:
    title = "fail2ban protects the SSH service"
    fix = "sudo apt install fail2ban, then enable the [sshd] jail in /etc/fail2ban/jail.local."
    if not ctx.exists("/etc/fail2ban/jail.conf"):
        return Result("F2B-001", "Intrusion prevention", title, WARN,
                      "fail2ban is not installed", fix, "medium")
    cp = configparser.ConfigParser(interpolation=None, strict=False)
    files = ([ctx.path("/etc/fail2ban/jail.conf"), ctx.path("/etc/fail2ban/jail.local")]
             + ctx.glob("/etc/fail2ban/jail.d", "*.conf")
             + ctx.glob("/etc/fail2ban/jail.d", "*.local"))
    for f in files:
        try:
            cp.read_string(f.read_text(errors="replace"))
        except (OSError, configparser.Error):
            continue
    enabled = (cp.has_section("sshd")
               and cp.get("sshd", "enabled", fallback="false").strip().lower()
               in ("true", "yes", "1"))
    if enabled:
        return Result("F2B-001", "Intrusion prevention", title, PASS,
                      "[sshd] jail is enabled", fix, "medium")
    return Result("F2B-001", "Intrusion prevention", title, WARN,
                  "fail2ban is installed but the [sshd] jail is not enabled", fix, "medium")


# ------------------------------------------------------ file permissions

# (id, path, most permissive mode that is still acceptable, severity)
FILE_MODES = [
    ("FS-001", "/etc/passwd", 0o644, "medium"),
    ("FS-002", "/etc/group", 0o644, "medium"),
    ("FS-003", "/etc/shadow", 0o640, "high"),
    ("FS-004", "/etc/gshadow", 0o640, "high"),
    ("FS-005", "/etc/ssh/sshd_config", 0o600, "low"),
]


def check_file_modes(ctx: Context) -> List[Result]:
    results = []
    for rid, path, allowed, sev in FILE_MODES:
        title = f"{path} has mode {allowed:04o} or stricter"
        fix = f"sudo chmod {allowed:04o} {path}"
        f = ctx.path(path)
        if not f.exists():
            results.append(Result(rid, "Files", title, SKIP, "file not found", fix, sev))
            continue
        mode = stat.S_IMODE(f.stat().st_mode)
        extra = mode & ~allowed
        if extra == 0:
            results.append(Result(rid, "Files", title, PASS, f"mode is {mode:04o}", fix, sev))
        else:
            status = FAIL if extra & 0o007 else WARN
            results.append(Result(rid, "Files", title, status,
                                  f"mode is {mode:04o}", fix, sev))
    return results


def check_world_writable(ctx: Context) -> Result:
    title = "No world-writable files under /etc"
    fix = "chmod o-w on each listed file after checking why it was writable."
    etc = ctx.path("/etc")
    if not etc.is_dir():
        return Result("FS-010", "Files", title, SKIP, "/etc not found", fix, "high")
    bad = []
    for dirpath, _dirs, files in os.walk(etc):
        for name in files:
            full = os.path.join(dirpath, name)
            try:
                st = os.lstat(full)
            except OSError:
                continue
            if stat.S_ISREG(st.st_mode) and st.st_mode & 0o002:
                bad.append("/" + os.path.relpath(full, ctx.root))
    if not bad:
        return Result("FS-010", "Files", title, PASS, "none found", fix, "high")
    shown = ", ".join(sorted(bad)[:5]) + (" ..." if len(bad) > 5 else "")
    return Result("FS-010", "Files", title, FAIL, f"{len(bad)} found: {shown}", fix, "high")


# ------------------------------------------------------------------ users

def check_users(ctx: Context) -> List[Result]:
    results = []
    passwd = ctx.read("/etc/passwd")
    fix1 = "Remove the extra UID 0 account or give it a unique UID."
    t1 = "Only root has UID 0"
    if passwd is None:
        results.append(Result("USR-001", "Accounts", t1, SKIP, "/etc/passwd not found", fix1, "high"))
    else:
        extra = [ln.split(":")[0] for ln in passwd.splitlines()
                 if ln.count(":") >= 6 and ln.split(":")[2] == "0" and ln.split(":")[0] != "root"]
        if extra:
            results.append(Result("USR-001", "Accounts", t1, FAIL,
                                  "extra UID 0 accounts: " + ", ".join(extra), fix1, "high"))
        else:
            results.append(Result("USR-001", "Accounts", t1, PASS, "only root", fix1, "high"))

    shadow = ctx.read("/etc/shadow")
    fix2 = "Lock the account with 'sudo passwd -l <user>' or set a password."
    t2 = "No account has an empty password"
    if shadow is None:
        results.append(Result("USR-002", "Accounts", t2, SKIP,
                              "/etc/shadow not readable (run as root)", fix2, "high"))
    else:
        empty = [ln.split(":")[0] for ln in shadow.splitlines()
                 if ln.count(":") >= 2 and ln.split(":")[1] == ""]
        if empty:
            results.append(Result("USR-002", "Accounts", t2, FAIL,
                                  "empty password: " + ", ".join(empty), fix2, "high"))
        else:
            results.append(Result("USR-002", "Accounts", t2, PASS, "none found", fix2, "high"))
    return results


# ------------------------------------------------------------------ ports

RISKY_PORTS = {
    21: "FTP", 23: "Telnet", 111: "rpcbind", 445: "SMB", 3306: "MySQL",
    5432: "PostgreSQL", 6379: "Redis", 11211: "memcached", 27017: "MongoDB",
}


def check_ports(ctx: Context) -> Result:
    title = "No risky service is exposed on all interfaces"
    fix = "Bind the service to 127.0.0.1 or block the port in the firewall."
    out = ctx.run(["ss", "-tuln"])
    if out is None:
        return Result("NET-001", "Network", title, SKIP,
                      "needs a live host with 'ss' available", fix, "high")
    exposed = set()
    for line in out.splitlines():
        cols = line.split()
        if len(cols) < 5 or cols[0] == "Netid":
            continue
        addr, _, port = cols[4].rpartition(":")
        if addr in ("0.0.0.0", "*", "[::]", "::") and port.isdigit():
            exposed.add(int(port))
    risky = sorted(p for p in exposed if p in RISKY_PORTS)
    listing = ", ".join(str(p) for p in sorted(exposed)) or "none"
    if risky:
        names = ", ".join(f"{p} ({RISKY_PORTS[p]})" for p in risky)
        return Result("NET-001", "Network", title, FAIL,
                      f"risky ports open: {names}; all public ports: {listing}", fix, "high")
    return Result("NET-001", "Network", title, PASS,
                  f"public ports: {listing}", fix, "high")


# ----------------------------------------------------------------- sysctl

def _sysctl_from_files(ctx: Context) -> dict:
    values: dict = {}
    files = ctx.glob("/etc/sysctl.d", "*.conf") + [ctx.path("/etc/sysctl.conf")]
    for f in files:
        try:
            text = f.read_text(errors="replace")
        except OSError:
            continue
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line[0] in "#;" or "=" not in line:
                continue
            key, val = line.split("=", 1)
            values[key.strip().lstrip("-").replace("/", ".")] = val.strip()
    return values


SYSCTL_RULES: List[Tuple[str, str, Callable[[str], bool], str, str]] = [
    ("SYS-001", "net.ipv4.tcp_syncookies", lambda v: v == "1",
     "SYN cookies are enabled (SYN flood protection)", "medium"),
    ("SYS-002", "net.ipv4.conf.all.rp_filter", lambda v: v in ("1", "2"),
     "Reverse path filtering is enabled", "medium"),
    ("SYS-003", "net.ipv4.conf.all.accept_redirects", lambda v: v == "0",
     "ICMP redirects are not accepted", "medium"),
    ("SYS-004", "net.ipv4.ip_forward", lambda v: v == "0",
     "IP forwarding is off (unless this host is a router)", "low"),
    ("SYS-005", "kernel.randomize_va_space", lambda v: v == "2",
     "Full ASLR is enabled", "medium"),
]


def check_sysctl(ctx: Context) -> List[Result]:
    configured = {} if ctx.live else _sysctl_from_files(ctx)
    results = []
    for rid, key, ok, title, sev in SYSCTL_RULES:
        fix = f"echo '{key} = <value>' | sudo tee /etc/sysctl.d/99-hardening.conf && sudo sysctl --system"
        value = None
        if ctx.live:
            try:
                value = Path("/proc/sys", *key.split(".")).read_text().strip()
            except OSError:
                value = None
        else:
            value = configured.get(key)
        if value is None:
            results.append(Result(rid, "Kernel", title, SKIP, "setting not found", fix, sev))
        else:
            results.append(Result(rid, "Kernel", title, PASS if ok(value) else FAIL,
                                  f"{key} = {value}", fix, sev))
    return results


# --------------------------------------------------------- auto updates

def check_auto_updates(ctx: Context) -> Result:
    title = "Automatic security updates are enabled"
    fix = "sudo apt install unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades"
    if not ctx.exists("/etc/apt"):
        return Result("UPD-001", "Updates", title, SKIP,
                      "not a Debian/Ubuntu system", fix, "medium")
    text = ctx.read("/etc/apt/apt.conf.d/20auto-upgrades") or ""
    if re.search(r'Unattended-Upgrade\s+"1"', text):
        return Result("UPD-001", "Updates", title, PASS,
                      "unattended upgrades are on", fix, "medium")
    return Result("UPD-001", "Updates", title, WARN,
                  "unattended upgrades are not enabled", fix, "medium")


# ---------------------------------------------------------------- runner

CHECKS = [
    check_ssh, check_firewall, check_fail2ban, check_file_modes,
    check_world_writable, check_users, check_ports, check_sysctl,
    check_auto_updates,
]


def run_all(ctx: Context) -> List[Result]:
    results: List[Result] = []
    for fn in CHECKS:
        try:
            out = fn(ctx)
        except Exception as exc:  # one broken check must not kill the report
            results.append(Result(fn.__name__, "Internal", fn.__name__, SKIP,
                                  f"check crashed: {exc}", "", "low"))
            continue
        results.extend(out if isinstance(out, list) else [out])
    return results
