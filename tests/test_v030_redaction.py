"""0.3.0 fail-closed line redaction (spec E)."""

from __future__ import annotations

import pytest

from lgs_switch_mcp.connection import redact_show_output
from lgs_switch_mcp.redaction import (
    REDACTED,
    REDACTED_LINE,
    redact_device_text,
    redact_sensitive_lines,
)
from tests.fakes import RUNNING_CONFIG, SECRETS_IN_RUNNING


def test_running_config_has_no_secrets() -> None:
    out = redact_device_text(RUNNING_CONFIG)
    for secret in SECRETS_IN_RUNNING:
        assert secret not in out, secret
    # Structure stays readable.
    assert "interface gigabitethernet 0/3" in out
    assert "storm-control broadcast level 1000" in out
    assert "system location Default Location" in out
    assert "set switch-name LGS328PC" in out
    assert 'description "EoC Zigbee"' in out


def test_snmp_lines_keep_keywords_only() -> None:
    out = redact_sensitive_lines(
        "snmp community index old name OldSecretComm77 security none\n"
        "snmp user ro_user auth sha AuthKeyValue99 priv aes PrivKeyValue99\n"
        "snmp targetparams tp1 user v2sec security-model v2c message-processing v2c\n"
        "snmp engineid 80001234deadbeef\n"
        "snmp mystery secretvalue"
    ).splitlines()
    assert out[0] == f"snmp community index {REDACTED} name {REDACTED} security {REDACTED}"
    assert out[1] == f"snmp user ro_user auth sha {REDACTED} priv aes {REDACTED}"
    assert "v2sec" not in out[2] and "security-model v2c" in out[2]
    assert out[4] == REDACTED_LINE


def test_username_password_and_radius_key() -> None:
    out = redact_sensitive_lines(
        "username admin password 7 0123abcdSECRETHASH privilege 15\n"
        "radius-server host 192.0.2.50 key RadiusShared1"
    )
    assert "0123abcdSECRETHASH" not in out
    assert "RadiusShared1" not in out
    assert "username admin password" in out


def test_pem_block_becomes_one_line() -> None:
    text = "a\n-----BEGIN RSA PRIVATE KEY-----\nMIIEow\nxyz\n-----END RSA PRIVATE KEY-----\nb"
    assert redact_sensitive_lines(text) == f"a\n{REDACTED_LINE}\nb"


def test_unterminated_pem_hides_rest() -> None:
    text = "a\n-----BEGIN CERTIFICATE-----\nMIIB\nmore"
    assert redact_sensitive_lines(text) == f"a\n{REDACTED_LINE}"


def test_long_key_blob_line_removed() -> None:
    blob = "AAAAB3NzaC1yc2EAAAADAQABAAABAQC7" + "x9" * 20
    assert redact_sensitive_lines(f"ssh key {blob}") == REDACTED_LINE


@pytest.mark.parametrize(
    "line",
    [
        "Authentication protocol : MD5",
        "Privacy Protocol : None",
        "Port Gi0/3 is force-authorized",
        "    0 Unknown community name",
        "    12 Bad community names",
        "Description: monkey bars",
        "Port Gi0/1 privilege level 15",
    ],
)
def test_benign_lines_survive(line: str) -> None:
    assert redact_sensitive_lines(line) == line


@pytest.mark.parametrize(
    "line",
    [
        "Community Name: SomeOtherCommunity",
        "Security Name: v2sec",
        "Auth Key: 0xdeadbeef",
        "Shared Secret : hunter2",
        "Key : abc",
    ],
)
def test_sensitive_label_values_masked(line: str) -> None:
    out = redact_sensitive_lines(line)
    assert out.endswith(REDACTED)
    assert line.split(":", 1)[1].strip() not in out


def test_unknown_sensitive_line_removed() -> None:
    assert redact_sensitive_lines("crypto thing abc") == REDACTED_LINE
    assert redact_sensitive_lines("enable password-ish blob zz") == REDACTED_LINE


def test_redaction_is_idempotent() -> None:
    once = redact_device_text(RUNNING_CONFIG)
    assert redact_device_text(once) == once


def test_show_radius_is_strict() -> None:
    table = (
        "Index  Server         Port  Key\n"
        "-----  -------------  ----  -----------\n"
        "1      192.0.2.50     1812  RadiusShared1\n"
        "Retransmit : 3\n"
        "Shared Secret : RadiusShared1\n"
    )
    out = redact_show_output("show radius server", table)
    assert "RadiusShared1" not in out
    assert "Retransmit : 3" in out
    assert out.splitlines()[0] == REDACTED_LINE


def test_abbreviated_radius_show_is_strict_too() -> None:
    out = redact_show_output("sh rad server", "1  192.0.2.50  1812  RadiusShared1")
    assert out == REDACTED_LINE


def test_session_log_rewrite_applies_line_rules(tmp_path, monkeypatch) -> None:
    from lgs_switch_mcp.connection import redact_session_log_file

    path = tmp_path / "session.log"
    path.write_text("LGS328PC# show running-config\n" + RUNNING_CONFIG, encoding="utf-8")
    monkeypatch.setenv("SWITCH_SESSION_LOG", str(path))
    redact_session_log_file()
    body = path.read_text(encoding="utf-8")
    for secret in SECRETS_IN_RUNNING:
        assert secret not in body
    assert "LGS328PC# show running-config" in body
