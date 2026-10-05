# linux-hardening-audit

A small, **read-only** command line tool that audits the security configuration of a Linux host and produces a scored report with a concrete fix for every finding.

It uses only the Python standard library, never changes anything on the system it audits, and can also audit an **offline filesystem tree** (for example an extracted container image).

## Why I built it

I run Linux servers and websites, and hardening them (SSH, firewall, fail2ban, file permissions) is a routine I repeat on every new machine. This tool turns that checklist into code, so the result is repeatable, scored, and easy to run in a script or a CI job.

## Features

- 23 checks across SSH, firewall, intrusion prevention, file permissions, accounts, network exposure, kernel settings and updates
- Weighted score from 0 to 100 (high, medium and low severity checks)
- A suggested fix for every warning and failure
- Text, JSON and Markdown reports
- `--fail-under` exit code for CI pipelines
- Offline mode with `--root` for container images and mounted disks
- sshd parsing that follows real sshd rules: first value wins, drop-in files in `sshd_config.d`, `Match` blocks ignored
- 19 unit tests

## Quick start

```bash
git clone https://github.com/patrickivanuellf/linux-hardening-audit.git
cd linux-hardening-audit

python3 -m hardening_audit                       # audit this host
sudo python3 -m hardening_audit                  # as root: also reads /etc/shadow
python3 -m hardening_audit --format md -o report.md
python3 -m hardening_audit --format json --fail-under 80
```

Options:

| Option | Meaning |
|---|---|
| `--root PATH` | Filesystem root to audit. Default `/` (live host) |
| `--format text\|json\|md` | Report format. Default `text` |
| `-o, --output FILE` | Write the report to a file |
| `--fail-under N` | Exit with status 1 if the score is below N |

### Audit a container image offline

```bash
docker create --name audit-target ubuntu:22.04
mkdir rootfs && docker export audit-target | tar -x -C rootfs
docker rm audit-target

python3 -m hardening_audit --root ./rootfs
```

Checks that need a running system (open ports, live kernel values) are marked `SKIP` in offline mode.

## What it checks

| ID | Area | Check | Severity |
|---|---|---|---|
| SSH-001 | SSH | Root login is disabled | high |
| SSH-002 | SSH | Password authentication is disabled | high |
| SSH-003 | SSH | Empty passwords are rejected | high |
| SSH-004 | SSH | `MaxAuthTries` is 4 or less | medium |
| SSH-005 | SSH | X11 forwarding is disabled | low |
| SSH-006 | SSH | `PermitUserEnvironment` is off | medium |
| FW-001 | Firewall | ufw is enabled | high |
| F2B-001 | Intrusion prevention | fail2ban `[sshd]` jail is enabled | medium |
| FS-001 to FS-005 | Files | Modes of `passwd`, `group`, `shadow`, `gshadow`, `sshd_config` | medium / high / low |
| FS-010 | Files | No world-writable files under `/etc` | high |
| USR-001 | Accounts | Only root has UID 0 | high |
| USR-002 | Accounts | No account has an empty password | high |
| NET-001 | Network | No risky service (Telnet, FTP, Redis, MySQL and others) listens on all interfaces | high |
| SYS-001 to SYS-005 | Kernel | SYN cookies, reverse path filter, ICMP redirects, IP forwarding, ASLR | medium / low |
| UPD-001 | Updates | Unattended security updates are enabled | medium |

## Scoring

Each check has a weight: high = 3, medium = 2, low = 1. A `PASS` earns the full weight, a `WARN` half, a `FAIL` nothing. `SKIP` checks are ignored. The score is the earned weight divided by the total weight, as a percentage.

## Sample output

This is an excerpt from a deliberately weak, fake filesystem tree built by `tests/builders.py`:

```bash
python3 -c "from tests.builders import make_weak; make_weak('demo/weak')"
python3 -m hardening_audit --root demo/weak
```

```text
Linux Hardening Audit v0.1.0
Target:    /tmp/demo/weak (offline tree)

[SSH]
  FAIL  SSH-001  Root login over SSH is disabled
            set to 'yes'
            fix: Set 'PermitRootLogin no' in /etc/ssh/sshd_config and reload sshd.
  FAIL  SSH-002  SSH password authentication is disabled
            set to 'yes'
            fix: Use key-based login, then set 'PasswordAuthentication no' and reload sshd.
  WARN  SSH-004  SSH limits authentication attempts (MaxAuthTries <= 4)
            set to 10
            fix: Set 'MaxAuthTries 3' (or 4).

[Accounts]
  FAIL  USR-001  Only root has UID 0
            extra UID 0 accounts: toor
  FAIL  USR-002  No account has an empty password
            empty password: guest

Summary: 4 passed, 3 warnings, 8 failed, 8 skipped
Score:   36/100
```

## Design notes

- **Read-only by design.** Checks only read files or run harmless commands (`ss -tuln`). There is no auto-fix mode on purpose: changing SSH or firewall settings blindly can lock you out of a server.
- **Offline-first.** Every file check goes through a `Context` object with a configurable root, which is what makes container audits and the unit tests possible without touching the real `/etc`.
- **One broken check never kills the report.** A check that crashes is reported as `SKIP` with the error.

## Limitations

- This is a learning and portfolio project, not a replacement for mature tools such as Lynis, OpenSCAP or CIS-CAT.
- The checks are Debian/Ubuntu oriented (ufw, apt) and cover a small, practical subset of common hardening guidance.
- File ownership is not checked, only permission modes. Modes survive `docker export`, but they are not tracked by git, so keep that in mind if you commit a fixture tree.
- Run as root to include checks that read `/etc/shadow`.

## Roadmap

- auditd, password aging and sudoers checks
- HTML report
- RHEL/Fedora support (firewalld, dnf-automatic)

## Development

```bash
pip install pytest
python3 -m pytest
```

Tested on Python 3.12.

## License

MIT. See [LICENSE](LICENSE).

Author: Patrick Ivanuell Firstyanto
