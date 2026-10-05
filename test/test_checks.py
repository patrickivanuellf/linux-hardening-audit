import json

from hardening_audit.checks import FAIL, PASS, SKIP, WARN, Context, run_all
from hardening_audit.cli import main
from hardening_audit.report import score
from tests.builders import make_hardened, make_weak, write


def results(root):
    return {r.id: r for r in run_all(Context(root))}


def test_weak_ssh_config_is_flagged(tmp_path):
    r = results(make_weak(tmp_path))
    assert r["SSH-001"].status == FAIL
    assert r["SSH-002"].status == FAIL
    assert r["SSH-004"].status == WARN
    assert r["SSH-005"].status == FAIL


def test_hardened_ssh_config_passes(tmp_path):
    r = results(make_hardened(tmp_path))
    for rid in ("SSH-001", "SSH-002", "SSH-003", "SSH-004", "SSH-005", "SSH-006"):
        assert r[rid].status == PASS, rid


def test_dropin_file_wins_over_main_config(tmp_path):
    write(tmp_path, "/etc/ssh/sshd_config", "PasswordAuthentication yes\n")
    write(tmp_path, "/etc/ssh/sshd_config.d/50-hardening.conf", "PasswordAuthentication no\n")
    assert results(tmp_path)["SSH-002"].status == PASS


def test_first_value_wins_inside_one_file(tmp_path):
    write(tmp_path, "/etc/ssh/sshd_config", "PasswordAuthentication no\nPasswordAuthentication yes\n")
    assert results(tmp_path)["SSH-002"].status == PASS


def test_match_block_is_ignored(tmp_path):
    write(tmp_path, "/etc/ssh/sshd_config",
          "PasswordAuthentication no\nMatch User bob\n  PasswordAuthentication yes\n")
    assert results(tmp_path)["SSH-002"].status == PASS


def test_missing_sshd_config_is_skipped(tmp_path):
    assert results(tmp_path)["SSH-001"].status == SKIP


def test_shadow_permissions(tmp_path):
    assert results(make_weak(tmp_path / "a"))["FS-003"].status == FAIL
    assert results(make_hardened(tmp_path / "b"))["FS-003"].status == PASS


def test_group_readable_sshd_config_is_only_a_warning(tmp_path):
    write(tmp_path, "/etc/ssh/sshd_config", "PermitRootLogin no\n", 0o640)
    assert results(tmp_path)["FS-005"].status == WARN


def test_extra_uid0_account_detected(tmp_path):
    r = results(make_weak(tmp_path))
    assert r["USR-001"].status == FAIL
    assert "toor" in r["USR-001"].detail


def test_empty_password_detected(tmp_path):
    r = results(make_weak(tmp_path))
    assert r["USR-002"].status == FAIL
    assert "guest" in r["USR-002"].detail


def test_world_writable_file_in_etc(tmp_path):
    make_hardened(tmp_path)
    write(tmp_path, "/etc/cron.d/backup", "* * * * * root true\n", 0o666)
    assert results(tmp_path)["FS-010"].status == FAIL


def test_fail2ban_states(tmp_path):
    assert results(make_weak(tmp_path / "a"))["F2B-001"].status == WARN
    assert results(make_hardened(tmp_path / "b"))["F2B-001"].status == PASS
    assert results(tmp_path / "empty")["F2B-001"].status == WARN


def test_ufw_states(tmp_path):
    assert results(make_weak(tmp_path / "a"))["FW-001"].status == FAIL
    assert results(make_hardened(tmp_path / "b"))["FW-001"].status == PASS


def test_sysctl_read_from_config_files(tmp_path):
    r = results(make_hardened(tmp_path))
    assert all(r[f"SYS-00{i}"].status == PASS for i in range(1, 6))


def test_live_only_checks_are_skipped_offline(tmp_path):
    assert results(make_hardened(tmp_path))["NET-001"].status == SKIP


def test_score_orders_weak_below_hardened(tmp_path):
    weak = score(run_all(Context(make_weak(tmp_path / "a"))))
    hard = score(run_all(Context(make_hardened(tmp_path / "b"))))
    assert hard == 100
    assert weak < 50


def test_cli_json_output_and_fail_under(tmp_path):
    root = make_weak(tmp_path / "root")
    out = tmp_path / "report.json"
    code = main(["--root", str(root), "--format", "json", "-o", str(out), "--fail-under", "80"])
    data = json.loads(out.read_text())
    assert code == 1
    assert data["score"] < 80
    assert any(r["id"] == "SSH-002" for r in data["results"])


def test_cli_exit_zero_when_score_is_high(tmp_path):
    root = make_hardened(tmp_path / "root")
    assert main(["--root", str(root), "--fail-under", "90", "-o", str(tmp_path / "r.txt")]) == 0


def test_cli_rejects_missing_root(tmp_path):
    assert main(["--root", str(tmp_path / "nope")]) == 2
