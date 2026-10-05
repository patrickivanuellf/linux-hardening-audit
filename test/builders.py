"""Helpers that build fake filesystem roots for tests""""
from pathlib import Path


def write(root, rel, text, mode=0o644):
    p = Path(root) / rel.lstrip("/")
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    p.chmod(mode)
    return p


def make_weak(root):
    write(root, "/etc/ssh/sshd_config",
          "PermitRootLogin yes\nPasswordAuthentication yes\n"
          "MaxAuthTries 10\nX11Forwarding yes\n")
    write(root, "/etc/passwd",
          "root:x:0:0:root:/root:/bin/bash\ntoor:x:0:0::/:/bin/sh\n")
    write(root, "/etc/shadow",
          "root:$6$abc:19000:0:99999:7:::\nguest::19000:0:99999:7:::\n", 0o644)
    write(root, "/etc/ufw/ufw.conf", "ENABLED=no\n")
    write(root, "/etc/fail2ban/jail.conf", "[DEFAULT]\nbantime = 10m\n")
    write(root, "/etc/apt/apt.conf.d/20auto-upgrades", 'APT::Periodic::Update-Package-Lists "1";\n')
    return Path(root)


def make_hardened(root):
    write(root, "/etc/ssh/sshd_config",
          "PermitRootLogin no\nPasswordAuthentication no\nPermitEmptyPasswords no\n"
          "MaxAuthTries 3\nX11Forwarding no\nPermitUserEnvironment no\n", 0o600)
    write(root, "/etc/passwd", "root:x:0:0:root:/root:/bin/bash\nweb:x:1000:1000::/home/web:/bin/bash\n")
    write(root, "/etc/shadow", "root:$6$abc:19000:0:99999:7:::\nweb:$6$def:19000:0:99999:7:::\n", 0o640)
    write(root, "/etc/ufw/ufw.conf", "ENABLED=yes\n")
    write(root, "/etc/fail2ban/jail.conf", "[DEFAULT]\nbantime = 10m\n")
    write(root, "/etc/fail2ban/jail.d/defaults.local", "[sshd]\nenabled = true\n")
    write(root, "/etc/sysctl.d/99-hardening.conf",
          "net.ipv4.tcp_syncookies = 1\nnet.ipv4.conf.all.rp_filter = 1\n"
          "net.ipv4.conf.all.accept_redirects = 0\nnet.ipv4.ip_forward = 0\n"
          "kernel.randomize_va_space = 2\n")
    write(root, "/etc/apt/apt.conf.d/20auto-upgrades", 'APT::Periodic::Unattended-Upgrade "1";\n')
    return Path(root)
