import errno
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from unittest.mock import MagicMock, patch

import pytest
from impacket.krb5 import constants
from impacket.krb5.kerberosv5 import KerberosError

from seamless_sso_browser import cli, errors
from seamless_sso_browser.cli import (
    _derive_okta_spn,
    _is_well_formed_sid,
    _okta_host_from_spn,
    parse_args,
)
from seamless_sso_browser.errors import (
    KdcUnreachableError,
    LocalEnvironmentError,
    TicketError,
    UsageError,
    sid_format_message,
)
from seamless_sso_browser.forger import merge_ccaches
from seamless_sso_browser.kerberos import _KDC_PORT, parse_user_sid
from tests.conftest import (
    REAL,
    make_dummy_ccache,
    make_dummy_kirbi,
    make_empty_ccache,
    run_main,
    run_main_subprocess,
)


class TestForgeryMode:
    FORGE_ARGS = [
        "--domain", "domain.local",
        "--user-sid", "S-1-5-21-111-222-333-1234",
        "--user", "admin",
        "--adssoacc-ntlm", "a" * 32,
    ]

    def test_minimal_forge_args(self):
        args = parse_args(self.FORGE_ARGS)
        assert args.domain == "domain.local"
        assert args.user_sid == "S-1-5-21-111-222-333-1234"
        assert args.user == "admin"
        assert args.adssoacc_ntlm == "a" * 32

    def test_aes_instead_of_ntlm(self):
        forge_aes = [
            "--domain", "d.local",
            "--user-sid", "S-1-5-21-111-222-333-1234",
            "--user", "admin",
            "--adssoacc-aes", "b" * 64,
        ]
        args = parse_args(forge_aes)
        assert args.adssoacc_aes == "b" * 64
        assert args.adssoacc_ntlm is None

    def test_requires_user_sid(self):
        with pytest.raises(SystemExit):
            parse_args([
                "--domain", "d.local", "--user", "u",
                "--adssoacc-ntlm", "a" * 32,
            ])

    def test_requires_user(self):
        with pytest.raises(SystemExit):
            parse_args([
                "--domain", "d.local",
                "--user-sid", "S-1-5-21-1-2-3-4",
                "--adssoacc-ntlm", "a" * 32,
            ])

    def test_requires_hash_or_aes(self):
        with pytest.raises(SystemExit):
            parse_args([
                "--domain", "d.local",
                "--user-sid", "S-1-5-21-1-2-3-4",
                "--user", "u",
            ])

    def test_ntlm_and_aes_mutually_exclusive(self):
        with pytest.raises(SystemExit):
            parse_args([
                "--domain", "d.local",
                "--user-sid", "S-1-5-21-1-2-3-4",
                "--user", "u",
                "--adssoacc-ntlm", "a" * 32,
                "--adssoacc-aes", "b" * 64,
            ])


class TestCredentialMode:
    def test_password_mode(self):
        args = parse_args([
            "--domain", "d.local", "--dc-ip", "10.0.0.1",
            "--user", "admin", "--password", "Pass1",
        ])
        assert args.password == "Pass1"

    def test_user_password_hash_mode(self):
        args = parse_args([
            "--domain", "d.local", "--dc-ip", "10.0.0.1",
            "--user", "admin", "--user-password-hash", "aa" * 16,
        ])
        assert args.user_password_hash == "aa" * 16

    def test_user_aes_key_mode(self):
        args = parse_args([
            "--domain", "d.local", "--dc-ip", "10.0.0.1",
            "--user", "admin", "--user-aes-key", "cc" * 32,
        ])
        assert args.user_aes_key == "cc" * 32

    def test_requires_dc_ip(self):
        with pytest.raises(SystemExit):
            parse_args([
                "--domain", "d.local", "--user", "admin",
                "--password", "Pass1",
            ])

    def test_requires_user(self):
        with pytest.raises(SystemExit):
            parse_args([
                "--domain", "d.local", "--dc-ip", "10.0.0.1",
                "--password", "Pass1",
            ])

    def test_requires_domain(self):
        with pytest.raises(SystemExit):
            parse_args([
                "--dc-ip", "10.0.0.1", "--user", "admin",
                "--password", "Pass1",
            ])


class TestTgtMode:
    def test_tgt_mode(self):
        args = parse_args([
            "--domain", "d.local", "--dc-ip", "10.0.0.1",
            "--tgt", "/tmp/tgt.ccache",
        ])
        assert args.tgt == "/tmp/tgt.ccache"

    def test_requires_dc_ip(self):
        with pytest.raises(SystemExit):
            parse_args(["--domain", "d.local", "--tgt", "/tmp/tgt.ccache"])

    def test_requires_domain(self):
        with pytest.raises(SystemExit):
            parse_args(["--dc-ip", "10.0.0.1", "--tgt", "/tmp/tgt.ccache"])


class TestTgsMode:
    def test_tgs_mode(self):
        args = parse_args(["--domain", "d.local", "--tgs", "/tmp/tgs.ccache"])
        assert args.tgs == "/tmp/tgs.ccache"

    def test_domain_still_required(self):
        with pytest.raises(SystemExit):
            parse_args(["--tgs", "/tmp/tgs.ccache"])


class TestCcacheMode:
    def test_ccache_mode(self):
        args = parse_args(["--domain", "d.local", "--ccache", "/tmp/test.ccache"])
        assert args.ccache == "/tmp/test.ccache"

    def test_skips_all_validation(self):
        args = parse_args(["--domain", "d.local", "--ccache", "/tmp/x.ccache"])
        assert args.user is None


class TestModeConflicts:
    def test_tgs_and_password_conflict(self):
        with pytest.raises(SystemExit):
            parse_args([
                "--domain", "d.local", "--dc-ip", "10.0.0.1",
                "--tgs", "/tmp/tgs.ccache", "--password", "pass",
            ])

    def test_tgt_and_adssoacc_conflict(self):
        with pytest.raises(SystemExit):
            parse_args([
                "--domain", "d.local", "--dc-ip", "10.0.0.1",
                "--tgt", "/tmp/tgt.ccache", "--adssoacc-ntlm", "a" * 32,
            ])

    def test_password_and_adssoacc_conflict(self):
        with pytest.raises(SystemExit):
            parse_args([
                "--domain", "d.local", "--dc-ip", "10.0.0.1",
                "--user", "admin", "--password", "pass",
                "--adssoacc-ntlm", "a" * 32,
            ])

    def test_no_auth_provided(self):
        with pytest.raises(SystemExit):
            parse_args(["--domain", "d.local"])


class TestCredentialFormatValidation:
    """C1.1/C1.3: a credential or key flag of the wrong shape exits 2, and the
    message names the flag and the length received rather than the key."""

    BASE = [
        "--domain", "domain.local", "--user", "admin",
        "--user-sid", "S-1-5-21-111-222-333-1234",
    ]
    # The --user-* key flags select credential mode, which wants --dc-ip, not --user-sid.
    CRED_BASE = ["--domain", "domain.local", "--user", "admin", "--dc-ip", "10.0.0.1"]
    OKTA_BASE = BASE + ["--idp", "okta", "--okta-org", "acme"]

    # Nothing could mistake this for a key, so its absence from a stream is meaningful.
    MARKER = "ZZZZ-MARKER-NOT-A-REAL-KEY"

    @pytest.mark.parametrize(
        ("base", "flag", "value", "lengths"),
        [
            (BASE, "--adssoacc-ntlm", "not-hex-at-all", (32,)),
            (BASE, "--adssoacc-ntlm", "a" * 31, (32,)),
            (BASE, "--adssoacc-ntlm", "z" * 32, (32,)),
            (BASE, "--adssoacc-ntlm", "", (32,)),
            (BASE, "--adssoacc-aes", "aabb", (32, 64)),
            (CRED_BASE, "--user-aes-key", "zz", (32, 64)),
            (OKTA_BASE, "--okta-svc-aes", "zzzz", (32, 64)),
        ],
    )
    def test_a_wrong_shaped_value_exits_two_naming_the_flag_and_the_length(
        self, base, flag, value, lengths, capsys
    ):
        with pytest.raises(SystemExit) as excinfo:
            parse_args([*base, flag, value])

        assert excinfo.value.code == 2
        expected = errors.hex_format_message(
            flag, expected_lengths=lengths, got_length=len(value)
        )
        assert expected in capsys.readouterr().err

    def test_an_empty_value_reports_zero_characters_not_a_missing_auth_mode(self, capsys):
        with pytest.raises(SystemExit) as excinfo:
            parse_args([*self.BASE, "--adssoacc-ntlm", ""])

        assert excinfo.value.code == 2
        err = capsys.readouterr().err
        assert errors.hex_format_message(
            "--adssoacc-ntlm", expected_lengths=(32,), got_length=0
        ) in err
        assert "No auth mode specified" not in err

    def test_the_rejected_value_reaches_neither_stream(self, capsys):
        with pytest.raises(SystemExit):
            parse_args([*self.BASE, "--adssoacc-ntlm", self.MARKER])

        captured = capsys.readouterr()
        assert self.MARKER not in captured.out
        assert self.MARKER not in captured.err

    def test_a_user_password_hash_that_is_not_hex_exits_two(self, capsys):
        with pytest.raises(SystemExit) as excinfo:
            parse_args([*self.CRED_BASE, "--user-password-hash", "nothex"])

        assert excinfo.value.code == 2
        assert errors.ntlm_hash_format_message(
            "--user-password-hash", got_length=6
        ) in capsys.readouterr().err

    def test_a_short_lm_half_is_the_half_reported(self, capsys):
        with pytest.raises(SystemExit) as excinfo:
            parse_args([*self.CRED_BASE, "--user-password-hash", "aa:" + "bb" * 16])

        assert excinfo.value.code == 2
        assert errors.ntlm_hash_format_message(
            "--user-password-hash", got_length=2
        ) in capsys.readouterr().err

    def test_both_halves_hex_is_accepted(self):
        value = "aa" * 16 + ":" + "bb" * 16
        args = parse_args([*self.CRED_BASE, "--user-password-hash", value])

        assert args.user_password_hash == value

    def test_a_bare_nt_hash_with_no_colon_is_accepted(self):
        args = parse_args([*self.CRED_BASE, "--user-password-hash", "aa" * 16])

        assert args.user_password_hash == "aa" * 16

    @pytest.mark.parametrize(
        ("base", "flag", "dest", "value"),
        [
            (BASE, "--adssoacc-ntlm", "adssoacc_ntlm", "A" * 32),
            (BASE, "--adssoacc-aes", "adssoacc_aes", "AABB" * 16),
            (BASE, "--adssoacc-aes", "adssoacc_aes", "ab" * 16),
            (CRED_BASE, "--user-aes-key", "user_aes_key", "F" * 64),
            (OKTA_BASE, "--okta-svc-aes", "okta_svc_aes", "0" * 32),
        ],
    )
    def test_a_valid_value_parses_with_its_case_intact(self, base, flag, dest, value):
        args = parse_args([*base, flag, value])

        assert getattr(args, dest) == value

    def test_a_bad_key_exits_two_in_a_real_process_with_no_traceback(self):
        result = run_main_subprocess([*self.BASE, "--adssoacc-ntlm", self.MARKER])

        assert result.returncode == 2
        assert "Traceback (most recent call last)" not in result.stderr
        assert self.MARKER not in result.stderr
        assert self.MARKER not in result.stdout
        # parser.error output is argparse's own; the handler adds no Error: line here.
        assert "Error: " not in result.stderr


class TestUserSidFormatValidation:
    """C1.2: a --user-sid that is not a well-formed SID exits 2 before any work."""

    BASE = ["--domain", "domain.local", "--user", "admin", "--adssoacc-ntlm", "a" * 32]

    @pytest.mark.parametrize("value", [
        "NOT-A-SID",
        "S",
        "S-1-5-21-1-2-3-abc",
        "S-1-5-32-1-2-3-4",  # a real SID shape, but not a domain authority
        "",
    ])
    def test_a_malformed_sid_exits_two_with_the_pinned_sentence(self, value, capsys):
        with pytest.raises(SystemExit) as excinfo:
            parse_args([*self.BASE, "--user-sid", value])

        assert excinfo.value.code == 2
        assert errors.sid_format_message(got=value) in capsys.readouterr().err

    def test_the_shape_is_checked_outside_forgery_mode_too(self, capsys):
        """The shape is wrong regardless of whether the run would have used the SID.

        --ccache y is a nonexistent path and stays one: no file-existence check lands in
        parse_args, so reaching the SID check is the only thing this proves.
        """
        with pytest.raises(SystemExit) as excinfo:
            parse_args(["--domain", "d", "--ccache", "y", "--user-sid", "NOT-A-SID"])

        assert excinfo.value.code == 2
        assert errors.sid_format_message(got="NOT-A-SID") in capsys.readouterr().err

    @pytest.mark.parametrize("value", [
        "S-1-5-21-111-222-333-1234",
        "S-1-5-21-1-2-3-4",
        "S-1-5-21-1111111111-2222222222-3333333333-1234",
    ])
    def test_a_well_formed_sid_parses_unchanged(self, value):
        args = parse_args([*self.BASE, "--user-sid", value])

        assert args.user_sid == value

    @pytest.mark.parametrize("sid", [
        "S-1-5-21-111-222-333-1234", "S-1-5-21-1-2-3-4",
        "NOT-A-SID", "S", "", "S-1-5-21-1-2-3-abc", "S-1-5-32-1-2-3-4",
        "S-1-5-21-1-2-3--4", "S-1-5-21-1-2-3-99999999999999999999",
        "S-1-5-21-1-2-3-+4",
    ])
    def test_the_argparse_check_and_parse_user_sid_agree(self, sid):
        """The point of the mirror: a disagreement is a run that passes argparse and
        then dies inside main() at the wrong exit code."""
        try:
            parse_user_sid(sid)
        except ValueError:
            accepted_by_library = False
        else:
            accepted_by_library = True

        assert _is_well_formed_sid(sid) is accepted_by_library


class TestTargetPresets:
    FORGE_ARGS = [
        "--domain", "domain.local",
        "--user-sid", "S-1-5-21-111-222-333-1234",
        "--user", "admin",
        "--adssoacc-ntlm", "a" * 32,
    ]

    def test_default_is_outlook(self):
        args = parse_args(self.FORGE_ARGS)
        assert args.target_url == "https://outlook.office365.com"

    def test_preset_outlook(self):
        args = parse_args(self.FORGE_ARGS + ["--target", "outlook"])
        assert args.target_url == "https://outlook.office365.com"

    def test_preset_sharepoint_with_tenant(self):
        args = parse_args(self.FORGE_ARGS + ["--target", "sharepoint", "--tenant", "contoso"])
        assert args.target_url == "https://contoso.sharepoint.com"

    def test_preset_sharepoint_without_tenant_errors(self):
        with pytest.raises(SystemExit):
            parse_args(self.FORGE_ARGS + ["--target", "sharepoint"])

    def test_preset_teams(self):
        args = parse_args(self.FORGE_ARGS + ["--target", "teams"])
        assert args.target_url == "https://teams.microsoft.com"

    def test_preset_onedrive(self):
        args = parse_args(self.FORGE_ARGS + ["--target", "onedrive"])
        assert args.target_url == "https://onedrive.live.com"

    def test_preset_admin(self):
        args = parse_args(self.FORGE_ARGS + ["--target", "admin"])
        assert args.target_url == "https://admin.microsoft.com"

    def test_preset_entra(self):
        args = parse_args(self.FORGE_ARGS + ["--target", "entra"])
        assert args.target_url == "https://entra.microsoft.com"

    def test_preset_azure(self):
        args = parse_args(self.FORGE_ARGS + ["--target", "azure"])
        assert args.target_url == "https://portal.azure.com"

    def test_raw_url_passthrough(self):
        args = parse_args(self.FORGE_ARGS + ["--target", "https://custom.example.com"])
        assert args.target_url == "https://custom.example.com"

    def test_raw_http_url_passthrough(self):
        args = parse_args(self.FORGE_ARGS + ["--target", "http://internal.test"])
        assert args.target_url == "http://internal.test"

    def test_unknown_preset_errors(self):
        with pytest.raises(SystemExit):
            parse_args(self.FORGE_ARGS + ["--target", "notarealpreset"])

    def test_preset_okta_dashboard(self):
        # C8.1: okta-dashboard is an Okta host, so it now requires --idp okta, and
        # Okta forgery is AES-only -- hence --okta-svc-aes rather than the Azure flag.
        args = parse_args([
            "--domain", "domain.local",
            "--user-sid", "S-1-5-21-111-222-333-1234",
            "--user", "admin",
            "--idp", "okta",
            "--okta-svc-aes", "a" * 64,
            "--target", "okta-dashboard",
            "--okta-org", "acme",
        ])
        assert args.target_url == "https://acme.okta.com"

    def test_preset_okta_dashboard_without_org_errors(self):
        with pytest.raises(SystemExit):
            parse_args(self.FORGE_ARGS + ["--target", "okta-dashboard"])

    @pytest.mark.parametrize(
        "cell,expected_host",
        [
            ("okta", "acme.okta.com"),
            ("oktapreview", "acme.oktapreview.com"),
            ("okta-emea", "acme.okta-emea.com"),
            ("okta-gov", "acme.okta-gov.com"),
        ],
    )
    def test_okta_dashboard_honors_cell(self, cell, expected_host):
        # okta-dashboard must follow --okta-domain, not hardcode .okta.com.
        args = parse_args([
            "--domain", "domain.local", "--idp", "okta",
            "--okta-org", "acme", "--okta-domain", cell,
            "--okta-svc-aes", "00" * 32,
            "--user-sid", "S-1-5-21-111-222-333-1234", "--user", "admin",
            "--target", "okta-dashboard",
        ])
        assert args.target_url == f"https://{expected_host}"


class TestDefaults:
    FORGE_ARGS = [
        "--domain", "domain.local",
        "--user-sid", "S-1-5-21-111-222-333-1234",
        "--user", "admin",
        "--adssoacc-ntlm", "a" * 32,
    ]

    def test_defaults(self):
        args = parse_args(self.FORGE_ARGS)
        assert args.target_url == "https://outlook.office365.com"
        assert args.no_cleanup is False
        assert args.verbose is False
        assert args.useragent is None

    def test_custom_useragent(self):
        args = parse_args(self.FORGE_ARGS + ["--useragent", "Custom/1.0"])
        assert args.useragent == "Custom/1.0"


class TestIdpSelection:
    def test_default_idp_is_azure(self):
        args = parse_args(["--domain", "x", "--ccache", "y"])
        assert args.idp == "azure"

    def test_idp_azure_explicit(self):
        args = parse_args(["--domain", "x", "--idp", "azure", "--ccache", "y"])
        assert args.idp == "azure"

    def test_idp_okta(self):
        args = parse_args([
            "--domain", "x", "--idp", "okta",
            "--okta-org", "acme", "--ccache", "y",
        ])
        assert args.idp == "okta"

    def test_okta_org_stored(self):
        args = parse_args([
            "--domain", "x", "--idp", "okta",
            "--okta-org", "acme", "--ccache", "y",
        ])
        assert args.okta_org == "acme"

    def test_okta_domain_default(self):
        args = parse_args([
            "--domain", "x", "--idp", "okta",
            "--okta-org", "acme", "--ccache", "y",
        ])
        assert args.okta_domain == "okta"

    def test_okta_domain_explicit(self):
        args = parse_args([
            "--domain", "x", "--idp", "okta",
            "--okta-org", "acme", "--okta-domain", "oktapreview",
            "--ccache", "y",
        ])
        assert args.okta_domain == "oktapreview"


class TestOktaSpnDerivation:
    def test_default_domain(self):
        assert _derive_okta_spn("acme", "okta") == "HTTP/acme.kerberos.okta.com"

    def test_oktapreview_domain(self):
        assert _derive_okta_spn("acme", "oktapreview") == "HTTP/acme.kerberos.oktapreview.com"

    def test_okta_emea_domain(self):
        assert _derive_okta_spn("acme", "okta-emea") == "HTTP/acme.kerberos.okta-emea.com"

    def test_okta_gov_domain(self):
        # The cell label is bare ("okta-gov"); the SPN carries the full base
        # domain (okta-gov.com) with no doubled ".com".
        assert _derive_okta_spn("acme", "okta-gov") == "HTTP/acme.kerberos.okta-gov.com"

    def test_an_empty_org_is_refused_rather_than_formatted(self):
        # S2-R10: the guard that stops "HTTP/None.kerberos.okta.com" being built. An
        # absent org is a programming error here -- the exempt modes derive the host
        # from the ticket instead -- so a plain ValueError, which main() renders as the
        # neutral unexpected-failure text at exit 1 without leaking the exception.
        with pytest.raises(ValueError):
            _derive_okta_spn("", "okta")


class TestOktaHostFromSpn:
    """S2-R10: which service principals read as an Okta Agentless DSSO SPN."""

    @pytest.mark.parametrize(
        "spn,expected",
        [
            ("HTTP/acme.kerberos.okta.com@TEST.LOCAL", "acme.kerberos.okta.com"),
            ("HTTP/acme.kerberos.okta.com", "acme.kerberos.okta.com"),
            ("http/acme.kerberos.oktapreview.com", "acme.kerberos.oktapreview.com"),
            ("HTTP/acme.kerberos.okta-emea.com", "acme.kerberos.okta-emea.com"),
            ("HTTP/acme.kerberos.okta-gov.com", "acme.kerberos.okta-gov.com"),
        ],
    )
    def test_an_okta_dsso_spn_yields_its_host(self, spn, expected):
        assert _okta_host_from_spn(spn) == expected

    @pytest.mark.parametrize(
        "spn",
        [
            "HTTP/autologon.microsoftazuread-sso.com@TEST.LOCAL",
            "HTTP/fileserver.kerberos.corp.local",
            "HTTP/.kerberos.okta.com",
            "cifs/acme.kerberos.okta.com",
            "krbtgt/TEST.LOCAL@TEST.LOCAL",
            "HTTP/acme.okta.com",
            "HTTP/",
            "notaprincipal",
        ],
    )
    def test_anything_else_yields_none(self, spn):
        assert _okta_host_from_spn(spn) is None


class TestOktaValidation:
    def test_okta_svc_aes_without_idp_okta_errors(self):
        with pytest.raises(SystemExit):
            parse_args([
                "--domain", "d", "--okta-svc-aes", "a" * 64,
                "--user", "u", "--user-sid", "S-1-5-21-1-2-3-4",
            ])

    def test_okta_domain_without_idp_okta_errors(self):
        with pytest.raises(SystemExit):
            parse_args([
                "--domain", "d", "--okta-domain", "oktapreview",
                "--ccache", "x",
            ])

    def test_azure_ntlm_with_idp_okta_errors(self):
        with pytest.raises(SystemExit):
            parse_args([
                "--domain", "d", "--idp", "okta", "--okta-org", "acme",
                "--adssoacc-ntlm", "a" * 32, "--user", "u",
                "--user-sid", "S-1-5-21-1-2-3-4",
            ])

    def test_azure_aes_with_idp_okta_errors(self):
        with pytest.raises(SystemExit):
            parse_args([
                "--domain", "d", "--idp", "okta", "--okta-org", "acme",
                "--adssoacc-aes", "a" * 64, "--user", "u",
                "--user-sid", "S-1-5-21-1-2-3-4",
            ])

    def test_idp_okta_without_okta_org_errors(self):
        with pytest.raises(SystemExit):
            parse_args([
                "--domain", "d", "--idp", "okta", "--okta-svc-aes", "a" * 64,
                "--user", "u", "--user-sid", "S-1-5-21-1-2-3-4",
            ])

    def test_idp_okta_ccache_without_okta_org_ok(self):
        args = parse_args([
            "--domain", "d", "--idp", "okta", "--ccache", "x",
        ])
        assert args.idp == "okta"

    def test_idp_okta_tgs_without_okta_org_ok(self):
        args = parse_args([
            "--domain", "d", "--idp", "okta", "--tgs", "x",
        ])
        assert args.idp == "okta"

    def test_okta_svc_aes_conflicts_with_password(self):
        with pytest.raises(SystemExit):
            parse_args([
                "--domain", "d", "--idp", "okta", "--okta-org", "acme",
                "--okta-svc-aes", "a" * 64, "--password", "pass",
                "--user", "u", "--dc-ip", "1.2.3.4",
            ])

    def test_okta_forgery_valid(self):
        args = parse_args([
            "--domain", "d", "--idp", "okta", "--okta-org", "acme",
            "--okta-svc-aes", "a" * 64, "--user", "u",
            "--user-sid", "S-1-5-21-1-2-3-4",
        ])
        assert args.okta_svc_aes == "a" * 64


class TestOktaIdpRequiredCrossChecks:
    """C8.1/C8.2: an Okta-only target or org under --idp azure exits 2 rather than
    launching a session whose trusted-uris cannot match its target."""

    def test_okta_dashboard_under_default_azure_exits_two(self, capsys):
        # C8.1/J1: the reproduction. --okta-org is required to reach this check at all,
        # because _resolve_target errors first without it.
        with pytest.raises(SystemExit) as excinfo:
            parse_args([
                "--domain", "d", "--ccache", "y",
                "--target", "okta-dashboard", "--okta-org", "acme",
            ])
        assert excinfo.value.code == 2
        message = errors.flag_requires_okta_idp_message("--target okta-dashboard")
        assert message in capsys.readouterr().err

    def test_okta_dashboard_under_explicit_azure_exits_two(self, capsys):
        # C8.1/J1: spelling --idp azure out is the same defect as letting it default.
        with pytest.raises(SystemExit) as excinfo:
            parse_args([
                "--domain", "d", "--ccache", "y", "--idp", "azure",
                "--target", "okta-dashboard", "--okta-org", "acme",
            ])
        assert excinfo.value.code == 2
        message = errors.flag_requires_okta_idp_message("--target okta-dashboard")
        assert message in capsys.readouterr().err

    def test_okta_dashboard_under_idp_okta_resolves(self):
        # C8.1: the check rejects the IdP mismatch, not the target itself.
        args = parse_args([
            "--domain", "d", "--ccache", "y", "--idp", "okta",
            "--target", "okta-dashboard", "--okta-org", "acme",
        ])
        assert args.target_url == "https://acme.okta.com"

    def test_okta_org_under_default_azure_exits_two(self, capsys):
        # C8.2/J2: once okta-dashboard is an error, --okta-org has no remaining effect
        # on the Azure path, so accepting it silently misleads.
        with pytest.raises(SystemExit) as excinfo:
            parse_args(["--domain", "d", "--ccache", "y", "--okta-org", "acme"])
        assert excinfo.value.code == 2
        assert errors.flag_requires_okta_idp_message("--okta-org") in capsys.readouterr().err

    def test_okta_org_under_explicit_azure_exits_two(self, capsys):
        # C8.2/J2: spelling --idp azure out is the same defect as letting it default.
        with pytest.raises(SystemExit) as excinfo:
            parse_args([
                "--domain", "d", "--ccache", "y", "--idp", "azure", "--okta-org", "acme",
            ])
        assert excinfo.value.code == 2
        assert errors.flag_requires_okta_idp_message("--okta-org") in capsys.readouterr().err

    def test_okta_org_under_idp_okta_is_stored(self):
        # C8.2: the check rejects the IdP mismatch, not --okta-org itself.
        args = parse_args([
            "--domain", "d", "--ccache", "y", "--idp", "okta", "--okta-org", "acme",
        ])
        assert args.okta_org == "acme"

    def test_raw_okta_url_under_azure_is_not_the_preset(self):
        # The target check matches the literal preset name. A raw URL that happens to
        # point at an Okta host is _resolve_target's passthrough, and stays accepted.
        args = parse_args([
            "--domain", "d", "--ccache", "y", "--target", "https://acme.okta.com",
        ])
        assert args.target_url == "https://acme.okta.com"

    def test_default_preset_under_idp_okta_is_untouched(self):
        # Neither check reaches the default target, so --idp okta still lands on outlook.
        args = parse_args([
            "--domain", "d", "--ccache", "y", "--idp", "okta", "--okta-org", "acme",
        ])
        assert args.target_url == "https://outlook.office365.com"

    def test_okta_dashboard_without_org_reports_the_org_error_first(self, capsys):
        # _resolve_target runs before _validate_mode, so for a doubly-bad argv its
        # --okta-org error wins. Accepted ordering, pinned here so nobody "fixes" it by
        # moving the _resolve_target call.
        with pytest.raises(SystemExit) as excinfo:
            parse_args(["--domain", "d", "--ccache", "y", "--target", "okta-dashboard"])
        assert excinfo.value.code == 2
        stderr = capsys.readouterr().err
        assert "--target okta-dashboard requires --okta-org" in stderr
        assert errors.flag_requires_okta_idp_message("--target okta-dashboard") not in stderr


class TestOpsecMessages:
    """Test that main() output messages use IDP-appropriate terminology."""

    def _run_main_with_argv(self, argv, capsys, parse_user_sid_ret=None):
        """Run main() with patched externals, return captured stdout."""
        patches = {}
        if parse_user_sid_ret:
            patches["parse_user_sid"] = MagicMock(return_value=parse_user_sid_ret)
        _, stdout, _ = run_main(argv, capsys, **patches)
        return stdout

    def test_okta_forgery_messages(self, capsys):
        output = self._run_main_with_argv(
            [
                "--domain", "d.local", "--idp", "okta", "--okta-org", "acme",
                "--okta-svc-aes", "a" * 64, "--user", "admin",
                "--user-sid", "S-1-5-21-1-2-3-4", "--no-cleanup",
            ],
            capsys,
            parse_user_sid_ret=("S-1-5-21-1-2-3", 4),
        )
        assert "Okta DSSO service account AES key" in output
        assert "Okta Agentless Desktop SSO" in output
        assert "AZUREADSSOACC$" not in output
        assert "both SSO SPNs" not in output

    def test_azure_forgery_messages_unchanged(self, capsys):
        output = self._run_main_with_argv(
            [
                "--domain", "d.local",
                "--adssoacc-ntlm", "a" * 32, "--user", "admin",
                "--user-sid", "S-1-5-21-1-2-3-4", "--no-cleanup",
            ],
            capsys,
            parse_user_sid_ret=("S-1-5-21-1-2-3", 4),
        )
        assert "AZUREADSSOACC$" in output
        assert "both SSO SPNs" not in output  # Azure forgery prints individual SPNs and merge
        assert "Okta" not in output

    def test_okta_credential_messages(self, capsys):
        output = self._run_main_with_argv(
            [
                "--domain", "d.local", "--idp", "okta", "--okta-org", "acme",
                "--dc-ip", "10.0.0.1", "--user", "admin",
                "--password", "Pass1", "--no-cleanup",
            ],
            capsys,
        )
        assert "Okta SSO SPN" in output
        assert "both SSO SPNs" not in output


class TestLaunchBannerRegister:
    """S2-R19/C10.1: the two launch-banner lines sit after the branched profile and
    forgery messages, so they look branched and are not. Each IdP must read its own
    wording, and neither register may name the other vendor's product."""

    AZURE_FORGERY = [
        "--domain", "d.local",
        "--adssoacc-ntlm", "a" * 32, "--user", "admin",
        "--user-sid", "S-1-5-21-1111111111-2222222222-3333333333-1234",
        "--no-cleanup",
    ]
    OKTA_FORGERY = [
        "--domain", "d.local", "--idp", "okta", "--okta-org", "acme",
        "--okta-svc-aes", "a" * 64, "--user", "admin",
        "--user-sid", "S-1-5-21-1111111111-2222222222-3333333333-1234",
        "--no-cleanup",
    ]
    AZURE_BANNER_PROMPT = (
        "[*] When the login page appears, enter the user's email and press Enter."
    )
    AZURE_BANNER_REST = (
        "[*] Seamless SSO will handle the rest — no password prompt should appear."
    )

    def test_the_azure_banner_is_byte_for_byte_what_it_is_today(self, capsys):
        # The control every assertion below rests on, and the line S2-R19 freezes:
        # Azure keeps both lines exactly, em dash included.
        _, stdout, _ = run_main(self.AZURE_FORGERY, capsys)

        assert self.AZURE_BANNER_PROMPT in stdout
        assert self.AZURE_BANNER_REST in stdout

    def test_the_azure_banner_names_no_okta(self, capsys):
        # Passes today. Read the register rather than restating it.
        _, stdout, _ = run_main(self.AZURE_FORGERY, capsys)

        leaked = [t for t in errors.forbidden_terms(errors.IDP_AZURE) if t in stdout]
        assert not leaked

    def test_the_okta_banner_names_no_microsoft_product(self, capsys):
        _, stdout, _ = run_main(self.OKTA_FORGERY, capsys)

        leaked = [t for t in errors.forbidden_terms(errors.IDP_OKTA) if t in stdout]
        assert not leaked, f"the Okta launch banner names {leaked}"

    def test_the_okta_banner_is_not_the_azure_one(self, capsys):
        # The positive half: Okta gets its own wording, not silence and not Azure's.
        _, stdout, _ = run_main(self.OKTA_FORGERY, capsys)

        assert self.AZURE_BANNER_REST not in stdout
        assert "no password prompt should appear" in stdout

    def test_the_okta_banner_names_the_okta_flow(self, capsys):
        # The positive half of S2-R19: Okta gets wording that describes the Okta
        # sign-in widget and Agentless Desktop SSO, not silence where Azure had a line.
        _, stdout, _ = run_main(self.OKTA_FORGERY, capsys)

        assert "Okta sign-in widget" in stdout
        assert "Agentless Desktop SSO will handle the rest" in stdout


class TestIdpReachesLaunchFirefox:
    """S2-R20/C10.3: cli.py tells launch_firefox which IdP it is launching for."""

    @pytest.mark.parametrize(
        "argv,expected",
        [
            (
                [
                    "--domain", "d.local",
                    "--adssoacc-ntlm", "a" * 32, "--user", "admin",
                    "--user-sid", "S-1-5-21-1111111111-2222222222-3333333333-1234",
                ],
                "azure",
            ),
            (
                [
                    "--domain", "d.local", "--idp", "okta", "--okta-org", "acme",
                    "--okta-svc-aes", "a" * 64, "--user", "admin",
                    "--user-sid", "S-1-5-21-1111111111-2222222222-3333333333-1234",
                ],
                "okta",
            ),
        ],
    )
    def test_the_parsed_idp_is_passed_by_keyword(self, capsys, argv, expected):
        launch = MagicMock()

        exit_code, _, _ = run_main(argv, capsys, launch_firefox=launch)

        assert exit_code == 0
        launch.assert_called_once()
        assert launch.call_args[1]["idp"] == expected


class TestIgnoredFlagWarnings:
    """C8.3: --user-sid outside forgery mode warns on stderr and changes nothing else."""

    VALID_SID = "S-1-5-21-1111111111-2222222222-3333333333-1234"

    @staticmethod
    def _expected_warning() -> str:
        """The warning text, built from the builder so the test cannot drift from it."""
        return errors.flag_ignored_message("--user-sid", because=cli._USER_SID_IGNORED_BECAUSE)

    # No exit code is asserted on the --ccache/--tgs/--tgt rows. They pass paths that do not
    # exist, and a later part of this stage (S2-R6, S2-R7) turns that into an exit-3
    # TicketError. The warning still fires there, being emitted before any ticket is read,
    # but the exit code is not this task's to pin -- do not tighten these rows.
    @pytest.mark.parametrize(
        "argv",
        [
            ["--domain", "d.local", "--ccache", "y"],
            ["--domain", "d.local", "--tgs", "y"],
            ["--domain", "d.local", "--dc-ip", "1.2.3.4", "--tgt", "y"],
            ["--domain", "d.local", "--dc-ip", "1.2.3.4", "--user", "u", "--password", "p"],
        ],
        ids=["ccache", "tgs", "tgt", "credential"],
    )
    def test_user_sid_outside_forgery_mode_warns_on_stderr(self, argv, capsys):
        _, _, stderr = run_main([*argv, "--user-sid", self.VALID_SID], capsys)
        assert self._expected_warning() in stderr
        assert stderr.startswith("Warning: ")

    def test_the_warning_leaves_the_exit_code_and_the_stdout_narration_alone(self, capsys):
        exit_code, stdout, stderr = run_main(
            [
                "--domain", "d.local", "--dc-ip", "1.2.3.4", "--user", "u", "--password", "p",
                "--user-sid", self.VALID_SID,
            ],
            capsys,
        )
        assert exit_code == 0
        assert "[*] Authenticating as" in stdout
        assert self._expected_warning() in stderr
        assert stderr.count("Warning: ") == 1
        assert "Error: " not in stderr

    def test_forgery_mode_reads_the_sid_so_it_is_silent(self, capsys):
        exit_code, _, stderr = run_main(
            [
                "--domain", "d.local", "--user", "admin", "--adssoacc-ntlm", "a" * 32,
                "--user-sid", self.VALID_SID,
            ],
            capsys,
        )
        assert exit_code == 0
        assert "Warning: " not in stderr

    # The other two flags decision (e) settles are deliberately silent, so both of these
    # assert the absence of a warning and nothing about the exit code.
    def test_tenant_without_target_sharepoint_is_redundant_not_ignored(self, capsys):
        _, _, stderr = run_main(
            ["--domain", "d.local", "--ccache", "y", "--tenant", "acme"], capsys
        )
        assert "Warning: " not in stderr

    def test_user_feeds_display_name_so_it_is_never_warned_about(self, capsys):
        _, _, stderr = run_main(
            ["--domain", "d.local", "--ccache", "y", "--user", "admin"], capsys
        )
        assert "Warning: " not in stderr


class TestCcacheValidation:
    """S2-R6/C6: --ccache is validated before any work, so an unusable ccache exits 3
    instead of narrating a success that never happened."""

    BASE = ["--domain", "d.local"]

    def test_a_nonexistent_ccache_no_longer_exits_zero(self, capsys, tmp_path):
        # C6, the worst defect in the run: at the baseline this exits 0 having printed
        # the full success banner, including the promise about the password prompt.
        missing = str(tmp_path / "does-not-exist.ccache")
        exit_code, stdout, stderr = run_main([*self.BASE, "--ccache", missing], capsys)

        assert exit_code == 3
        assert "[*] Launching Firefox as" not in stdout
        assert "no password prompt should appear" not in stdout
        assert "[*] Using pre-forged ccache" not in stdout
        assert stderr == (
            "Error: "
            + errors.ticket_file_message(
                missing, reason=errors.TICKET_REASON_MISSING, flag="--ccache"
            )
            + "\n"
        )

    @staticmethod
    def _a_directory(tmp_path) -> str:
        return str(tmp_path)

    @staticmethod
    def _an_unreadable_file(tmp_path) -> str:
        path = tmp_path / "unreadable.ccache"
        path.write_bytes(b"whatever")
        path.chmod(0o000)
        return str(path)

    @staticmethod
    def _a_base64_value(tmp_path) -> str:
        # --ccache is documented as a path. At the baseline this string is assigned
        # straight to KRB5CCNAME and Firefox silently holds no ticket, at exit 0.
        return "BQQADAABAAgAAAAAAAAAAA=="

    @staticmethod
    def _a_zero_byte_file(tmp_path) -> str:
        path = tmp_path / "zero.ccache"
        path.write_bytes(b"")
        return str(path)

    @staticmethod
    def _a_garbage_file(tmp_path) -> str:
        path = tmp_path / "garbage.bin"
        path.write_bytes(b"\x00\x01\x02not a ticket at all\xff")
        return str(path)

    @staticmethod
    def _an_empty_credentials_ccache(tmp_path) -> str:
        source = str(tmp_path / "source.ccache")
        empty = str(tmp_path / "empty.ccache")
        make_dummy_ccache(source, "HTTP/autologon.microsoftazuread-sso.com")
        make_empty_ccache(source, empty)
        return empty

    @pytest.mark.parametrize(
        "make,expected_fragment",
        [
            (_a_directory, "it is a directory, not a ticket file"),
            (_an_unreadable_file, "permission denied"),
            (_a_base64_value, "no such file"),
            (_a_zero_byte_file, "not a valid ccache or kirbi"),
            (_a_garbage_file, "not a valid ccache or kirbi"),
            (_an_empty_credentials_ccache, "it holds no credentials"),
        ],
        ids=["directory", "unreadable", "base64", "zero-byte", "garbage", "no-credentials"],
    )
    def test_every_unusable_ccache_exits_three_with_its_own_reason(
        self, make, expected_fragment, capsys, tmp_path
    ):
        value = make.__func__(tmp_path)
        try:
            exit_code, stdout, stderr = run_main(
                [*self.BASE, "--ccache", value], capsys
            )
        finally:
            # Restore the unreadable fixture's mode so tmp_path teardown can remove it.
            unreadable = tmp_path / "unreadable.ccache"
            if unreadable.exists():
                unreadable.chmod(0o600)

        assert exit_code == 3
        assert expected_fragment in stderr
        assert "Traceback (most recent call last)" not in stderr
        assert "[*] Launching Firefox as" not in stdout

    def test_a_ccache_in_an_unreadable_directory_still_exits_three(self, capsys, tmp_path):
        # os.path.isfile is False when the parent cannot be listed, so this reports as a
        # missing file. Whichever reason it reports, it must never be exit 0.
        parent = tmp_path / "locked"
        parent.mkdir()
        target = parent / "x.ccache"
        target.write_bytes(b"whatever")
        parent.chmod(0o000)
        try:
            exit_code, _, stderr = run_main([*self.BASE, "--ccache", str(target)], capsys)
        finally:
            parent.chmod(0o700)

        assert exit_code == 3
        assert str(target) in stderr
        assert "Traceback (most recent call last)" not in stderr

    def test_a_valid_ccache_still_launches_and_is_not_ours_to_delete(self, capsys, tmp_path):
        # The regression half: validating somebody else's ccache must not make the tool
        # responsible for deleting it. cleanup's second argument is the ccache it owns.
        ccache = str(tmp_path / "good.ccache")
        make_dummy_ccache(ccache, "HTTP/autologon.microsoftazuread-sso.com")
        cleanup = MagicMock()

        exit_code, stdout, _ = run_main(
            [*self.BASE, "--ccache", ccache], capsys, cleanup=cleanup
        )

        assert exit_code == 0
        assert f"[*] Using pre-forged ccache: {ccache}" in stdout
        assert "[*] Launching Firefox as" in stdout
        assert cleanup.call_args[0][1] is None
        assert os.path.isfile(ccache)


class TestTicketKindValidation:
    """S2-R7/C6.2: --tgs given a TGT and --tgt given a service ticket each exit 3 naming
    the flag that would have worked, instead of launching a useless session."""

    SERVICE_SPN = "HTTP/autologon.microsoftazuread-sso.com"
    TGT_SPN = "krbtgt/test.local"

    def test_tgs_given_a_tgt_exits_three_and_never_claims_success(self, capsys, tmp_path):
        # At the baseline: "[+] TGS imported successfully" and exit 0, with a ccache
        # holding no service ticket at all.
        tgt = str(tmp_path / "tgt.ccache")
        make_dummy_ccache(tgt, self.TGT_SPN)

        exit_code, stdout, stderr = run_main(
            ["--domain", "d.local", "--tgs", tgt], capsys
        )

        assert exit_code == 3
        assert "[+] TGS imported successfully" not in stdout
        assert "[*] Launching Firefox as" not in stdout
        assert "Error: the ticket is for krbtgt/" in stderr
        assert "--tgt" in stderr
        assert "Traceback (most recent call last)" not in stderr

    def test_tgt_given_a_service_ticket_exits_three_naming_tgs(self, capsys, tmp_path):
        # C10. At the baseline this is an impacket failure through the catch-all: exit 1,
        # "unexpected ...", and nothing the operator can act on.
        tgs = str(tmp_path / "tgs.ccache")
        make_dummy_ccache(tgs, self.SERVICE_SPN)

        exit_code, stdout, stderr = run_main(
            ["--domain", "d.local", "--dc-ip", "1.2.3.4", "--tgt", tgs], capsys
        )

        assert exit_code == 3
        assert "[*] Importing TGT from" not in stdout
        assert f"Error: the ticket is for {self.SERVICE_SPN}" in stderr
        assert "--tgs" in stderr
        assert "Traceback (most recent call last)" not in stderr

    def test_the_kind_check_reads_a_kirbi_the_same_way(self, capsys, tmp_path):
        # --tgs accepts kirbi as well as ccache; the kind must not depend on the container.
        ccache = str(tmp_path / "tgt.ccache")
        kirbi = str(tmp_path / "tgt.kirbi")
        make_dummy_ccache(ccache, self.TGT_SPN)
        make_dummy_kirbi(ccache, kirbi)

        exit_code, _, stderr = run_main(["--domain", "d.local", "--tgs", kirbi], capsys)

        assert exit_code == 3
        assert "the ticket is for krbtgt/" in stderr

    @pytest.mark.parametrize(
        "argv_tail,flag",
        [
            (["--tgs", "{path}"], "--tgs"),
            (["--dc-ip", "1.2.3.4", "--tgt", "{path}"], "--tgt"),
        ],
        ids=["tgs", "tgt"],
    )
    def test_a_ticket_with_no_credentials_exits_three_in_both_modes(
        self, argv_tail, flag, capsys, tmp_path
    ):
        # C8: the IndexError guard. credentials[0] is what both paths reach for next.
        source = str(tmp_path / "source.ccache")
        empty = str(tmp_path / "empty.ccache")
        make_dummy_ccache(source, self.SERVICE_SPN)
        make_empty_ccache(source, empty)
        argv = ["--domain", "d.local", *[a.format(path=empty) for a in argv_tail]]

        exit_code, _, stderr = run_main(argv, capsys)

        assert exit_code == 3
        assert errors.ticket_file_message(
            empty, reason=errors.TICKET_REASON_NO_CREDENTIALS, flag=flag
        ) in stderr

    def test_the_right_kind_still_works_in_each_mode(self, capsys, tmp_path):
        # The regression half: the check rejects the mismatch, not the flag.
        tgs = str(tmp_path / "tgs.ccache")
        tgt = str(tmp_path / "tgt.ccache")
        make_dummy_ccache(tgs, self.SERVICE_SPN)
        make_dummy_ccache(tgt, self.TGT_SPN)

        tgs_code, tgs_out, _ = run_main(["--domain", "d.local", "--tgs", tgs], capsys)
        assert tgs_code == 0
        assert "[+] TGS imported successfully" in tgs_out

        tgt_code, tgt_out, _ = run_main(
            ["--domain", "d.local", "--dc-ip", "1.2.3.4", "--tgt", tgt], capsys
        )
        assert tgt_code == 0
        assert "[*] Importing TGT from" in tgt_out

    def test_a_principal_with_no_service_class_is_treated_as_a_service_ticket(self):
        # A bare principal has no "/", so split("/", 1)[0] is the whole string: the
        # predicate must return False rather than raise, so --tgs accepts such a ticket.
        # Pinned on the predicate because make_dummy_ccache cannot build the ccache --
        # impacket's own ticketer reads spn.split("/")[1] and raises IndexError, for
        # "testuser" and "testuser@TEST.LOCAL" alike.
        assert cli._ticket_is_a_tgt(["testuser@TEST.LOCAL"]) is False
        assert cli._ticket_is_a_tgt(["testuser"]) is False

    def test_the_wrong_kind_message_reads_as_a_sentence(self, capsys, tmp_path):
        # ticket_kind_message appends "is required", so the expected kind has to stay a
        # noun phrase. A trailing advisory clause renders as the run-on "...to have the
        # DC issue one is required"; the remedy belongs in a parenthetical instead.
        tgt = str(tmp_path / "tgt.ccache")
        make_dummy_ccache(tgt, self.TGT_SPN)

        _, _, stderr = run_main(["--domain", "d.local", "--tgs", tgt], capsys)

        assert (
            "but a service ticket (pass a TGT with --tgt and --dc-ip to have the DC "
            "issue one) is required" in stderr
        )


class TestSpnMismatchWarning:
    """S2-R8/C6.3: an imported service ticket whose SPN no SSO host will present warns on
    stderr and the run continues, because the expected set is org-dependent and a false
    positive would block a working invocation."""

    AZURE_SPN = "HTTP/autologon.microsoftazuread-sso.com"
    AADG_SPN = "HTTP/aadg.windows.net.nsatc.net"
    OTHER_SPN = "HTTP/fileserver.corp.local"

    def test_an_expected_azure_spn_is_silent(self, capsys, tmp_path):
        ccache = str(tmp_path / "good.ccache")
        make_dummy_ccache(ccache, self.AZURE_SPN)

        exit_code, _, stderr = run_main(["--domain", "d.local", "--ccache", ccache], capsys)

        assert exit_code == 0
        assert "Warning: " not in stderr

    def test_an_unexpected_spn_warns_and_the_run_continues(self, capsys, tmp_path):
        # The reproduction: at the baseline this launches with no signal at all.
        ccache = str(tmp_path / "wrong.ccache")
        make_dummy_ccache(ccache, self.OTHER_SPN)

        exit_code, stdout, stderr = run_main(
            ["--domain", "d.local", "--ccache", ccache], capsys
        )

        assert exit_code == 0
        assert "[*] Launching Firefox as" in stdout
        assert stderr.startswith("Warning: ")
        assert self.OTHER_SPN in stderr
        assert self.AZURE_SPN in stderr
        assert "Error: " not in stderr

    def test_the_warning_goes_to_stderr_and_not_to_stdout(self, capsys, tmp_path):
        # All narration on stdout, all errors and warnings on stderr.
        ccache = str(tmp_path / "wrong.ccache")
        make_dummy_ccache(ccache, self.OTHER_SPN)

        _, stdout, stderr = run_main(["--domain", "d.local", "--ccache", ccache], capsys)

        assert "Warning: " not in stdout
        assert "continuing anyway" in stderr

    def test_tgs_mode_warns_the_same_way(self, capsys, tmp_path):
        tgs = str(tmp_path / "wrong.ccache")
        make_dummy_ccache(tgs, self.OTHER_SPN)

        exit_code, stdout, stderr = run_main(["--domain", "d.local", "--tgs", tgs], capsys)

        assert exit_code == 0
        assert "[+] TGS imported successfully" in stdout
        assert self.OTHER_SPN in stderr

    def test_idp_okta_with_an_org_expects_the_derived_okta_spn(self, capsys, tmp_path):
        ccache = str(tmp_path / "azure.ccache")
        make_dummy_ccache(ccache, self.AZURE_SPN)

        exit_code, _, stderr = run_main(
            ["--domain", "d.local", "--idp", "okta", "--okta-org", "acme",
             "--ccache", ccache],
            capsys,
        )

        assert exit_code == 0
        assert "Warning: " in stderr
        assert "HTTP/acme.kerberos.okta.com" in stderr

    def test_idp_okta_without_an_org_never_names_a_guessed_host(self, capsys, tmp_path):
        # S2-R10: --ccache and --tgs are exempt from --okta-org because the Okta host
        # comes from the ticket. An Azure ticket under --idp okta has no host to read,
        # so the run stops at exit 3 -- it never warns against, or writes, a guessed one.
        ccache = str(tmp_path / "azure.ccache")
        make_dummy_ccache(ccache, self.AZURE_SPN)

        exit_code, _, stderr = run_main(
            ["--domain", "d.local", "--idp", "okta", "--ccache", ccache], capsys
        )

        assert exit_code == 3
        assert "None.kerberos." not in stderr
        assert "Warning: " not in stderr
        assert stderr.startswith("Error: ")

    def test_one_matching_credential_among_several_is_silent(self, capsys, tmp_path):
        # The rule that keeps a working invocation working: at least one match -> silent.
        first = str(tmp_path / "a.ccache")
        second = str(tmp_path / "b.ccache")
        merged = str(tmp_path / "merged.ccache")
        make_dummy_ccache(first, self.OTHER_SPN)
        make_dummy_ccache(second, self.AADG_SPN)
        merge_ccaches(first, second, merged)

        exit_code, _, stderr = run_main(["--domain", "d.local", "--ccache", merged], capsys)

        assert exit_code == 0
        assert "Warning: " not in stderr

    def test_the_warning_never_reaches_the_forgery_or_credential_paths(self, capsys):
        # TestExitCodeSweepAcrossAProcess asserts stderr == f"Error: {message}\n" exactly on
        # a forgery invocation. Nothing this task adds may fire there.
        exit_code, _, stderr = run_main(
            ["--domain", "d.local", "--adssoacc-ntlm", "a" * 32, "--user", "admin",
             "--user-sid", "S-1-5-21-1111111111-2222222222-3333333333-1234"],
            capsys,
        )

        assert exit_code == 0
        assert stderr == ""


class TestOktaHostDerivation:
    """S2-R10/C7: under --idp okta with no --okta-org the Okta host comes from the
    imported ticket, and the literal None never reaches user.js or krb5.conf."""

    OKTA_SPN = "HTTP/acme.kerberos.okta.com"
    OKTA_HOST = "acme.kerberos.okta.com"
    AZURE_SPN = "HTTP/autologon.microsoftazuread-sso.com"
    LEAK = "None.kerberos."

    @staticmethod
    def _run_and_read(argv: list[str], capsys, work) -> tuple[int, str, str, str]:
        """Run main() with the real profile writers into work, and read what they wrote.

        Returns (exit_code, stderr, user.js text, krb5.conf text); the two texts are ""
        when the run failed before writing them.
        """
        work.mkdir(parents=True, exist_ok=True)
        with patch(
            "seamless_sso_browser.cli.tempfile.mkdtemp", return_value=str(work)
        ):
            exit_code, _, stderr = run_main(
                argv, capsys, create_firefox_profile=REAL, create_krb5_conf=REAL
            )
        user_js = work / "profile" / "user.js"
        krb5_conf = work / "krb5.conf"
        return (
            exit_code,
            stderr,
            user_js.read_text() if user_js.exists() else "",
            krb5_conf.read_text() if krb5_conf.exists() else "",
        )

    def test_the_azure_path_writes_the_default_hosts(self, capsys, tmp_path):
        # The control: trusted_uris=None and sso_hosts=None still mean "Azure defaults"
        # (NFR-3), so this run must be untouched by anything C7's fix does.
        ccache = str(tmp_path / "azure.ccache")
        make_dummy_ccache(ccache, self.AZURE_SPN)

        exit_code, _, user_js, krb5_conf = self._run_and_read(
            ["--domain", "d.local", "--ccache", ccache], capsys, tmp_path / "work"
        )

        assert exit_code == 0
        assert "autologon.microsoftazuread-sso.com" in user_js
        assert "autologon.microsoftazuread-sso.com" in krb5_conf
        assert self.LEAK not in user_js
        assert self.LEAK not in krb5_conf

    def test_an_explicit_okta_org_still_wins(self, capsys, tmp_path):
        # --okta-org given wins in every mode; S2-R10 changes nothing on this path.
        ccache = str(tmp_path / "okta.ccache")
        make_dummy_ccache(ccache, self.OKTA_SPN)

        exit_code, _, user_js, krb5_conf = self._run_and_read(
            [
                "--domain", "d.local", "--idp", "okta", "--okta-org", "acme",
                "--ccache", ccache,
            ],
            capsys,
            tmp_path / "work",
        )

        assert exit_code == 0
        assert f'"https://{self.OKTA_HOST}"' in user_js
        assert f"    {self.OKTA_HOST} = D.LOCAL" in krb5_conf

    def test_ccache_mode_without_an_org_derives_the_host_into_user_js(
        self, capsys, tmp_path
    ):
        ccache = str(tmp_path / "okta.ccache")
        make_dummy_ccache(ccache, self.OKTA_SPN)

        exit_code, _, user_js, _ = self._run_and_read(
            ["--domain", "d.local", "--idp", "okta", "--ccache", ccache],
            capsys,
            tmp_path / "work",
        )

        assert exit_code == 0
        assert self.LEAK not in user_js
        assert f'"https://{self.OKTA_HOST}"' in user_js

    def test_ccache_mode_without_an_org_derives_the_host_into_krb5_conf(
        self, capsys, tmp_path
    ):
        ccache = str(tmp_path / "okta.ccache")
        make_dummy_ccache(ccache, self.OKTA_SPN)

        exit_code, _, _, krb5_conf = self._run_and_read(
            ["--domain", "d.local", "--idp", "okta", "--ccache", ccache],
            capsys,
            tmp_path / "work",
        )

        assert exit_code == 0
        assert self.LEAK not in krb5_conf
        assert f"    {self.OKTA_HOST} = D.LOCAL" in krb5_conf

    def test_tgs_mode_without_an_org_derives_the_host(self, capsys, tmp_path):
        # --tgs is the other exempt mode. ccache_from_tgs is not patched by run_main,
        # so the ticket is really imported and the derived host must reach both files.
        ccache = str(tmp_path / "okta.ccache")
        make_dummy_ccache(ccache, self.OKTA_SPN)

        exit_code, _, user_js, krb5_conf = self._run_and_read(
            ["--domain", "d.local", "--idp", "okta", "--tgs", ccache],
            capsys,
            tmp_path / "work",
        )

        assert exit_code == 0
        assert self.LEAK not in user_js
        assert self.LEAK not in krb5_conf
        assert f'"https://{self.OKTA_HOST}"' in user_js

    def test_the_ticket_wins_over_the_okta_domain_flag(self, capsys, tmp_path):
        # Review Focus 1: the host is read out of the ticket, not rebuilt from
        # --okta-domain, whose default is "okta". A ticket from the gov cell must
        # derive the gov host even though the flag says otherwise.
        ccache = str(tmp_path / "gov.ccache")
        make_dummy_ccache(ccache, "HTTP/acme.kerberos.okta-gov.com")

        exit_code, _, user_js, krb5_conf = self._run_and_read(
            ["--domain", "d.local", "--idp", "okta", "--ccache", ccache],
            capsys,
            tmp_path / "work",
        )

        assert exit_code == 0
        assert '"https://acme.kerberos.okta-gov.com"' in user_js
        assert "    acme.kerberos.okta-gov.com = D.LOCAL" in krb5_conf

    def test_the_derived_host_is_the_one_the_ticket_carries_not_a_guess(
        self, capsys, tmp_path
    ):
        # A second org on a second cell: nothing in the code may hardcode "acme".
        ccache = str(tmp_path / "other.ccache")
        make_dummy_ccache(ccache, "HTTP/contoso.kerberos.oktapreview.com")

        exit_code, _, user_js, _ = self._run_and_read(
            ["--domain", "d.local", "--idp", "okta", "--ccache", ccache],
            capsys,
            tmp_path / "work",
        )

        assert exit_code == 0
        assert '"https://contoso.kerberos.oktapreview.com"' in user_js

    def test_an_azure_ticket_under_idp_okta_exits_three(self, capsys, tmp_path):
        # Review Focus 2: the likeliest real mistake. errors.py owns the text.
        ccache = str(tmp_path / "azure.ccache")
        make_dummy_ccache(ccache, self.AZURE_SPN)

        exit_code, stderr, user_js, krb5_conf = self._run_and_read(
            ["--domain", "d.local", "--idp", "okta", "--ccache", ccache],
            capsys,
            tmp_path / "work",
        )

        assert exit_code == 3
        assert stderr.startswith("Error: ")
        assert "--okta-org" in stderr
        assert "--idp azure" in stderr
        assert self.AZURE_SPN in stderr
        assert user_js == ""
        assert krb5_conf == ""

    def test_a_host_that_merely_contains_kerberos_is_not_an_okta_spn(
        self, capsys, tmp_path
    ):
        # Review Focus 3: the base domain must be one of OKTA_BASE_DOMAINS' four values.
        ccache = str(tmp_path / "decoy.ccache")
        make_dummy_ccache(ccache, "HTTP/fileserver.kerberos.corp.local")

        exit_code, stderr, _, _ = self._run_and_read(
            ["--domain", "d.local", "--idp", "okta", "--ccache", ccache],
            capsys,
            tmp_path / "work",
        )

        assert exit_code == 3
        assert "fileserver.kerberos.corp.local" in stderr


class TestRunMainHarness:
    """Test the in-process run_main harness in tests/conftest.py."""

    FORGE_ARGV = [
        "--domain", "d.local",
        "--adssoacc-ntlm", "a" * 32, "--user", "admin",
        "--user-sid", "S-1-5-21-1-2-3-4",
    ]

    @staticmethod
    def _parsed_sid():
        return MagicMock(return_value=("S-1-5-21-1-2-3", 4))

    def test_returns_exit_code_stdout_and_stderr_on_success(self, capsys):
        exit_code, stdout, stderr = run_main(
            [*self.FORGE_ARGV, "--no-cleanup"],
            capsys,
            parse_user_sid=self._parsed_sid(),
        )
        assert exit_code == 0
        assert "[*] Launching Firefox as" in stdout
        assert stderr == ""

    def test_patch_override_reaches_main(self, capsys):
        launch = MagicMock()
        exit_code, stdout, _ = run_main(
            [*self.FORGE_ARGV, "--no-cleanup"],
            capsys,
            parse_user_sid=self._parsed_sid(),
            find_firefox=MagicMock(return_value="/opt/custom/firefox"),
            launch_firefox=launch,
        )
        assert exit_code == 0
        assert "[*] Launching Firefox as" in stdout
        assert launch.call_args[1]["firefox_path"] == "/opt/custom/firefox"

    def test_real_sentinel_disables_the_default_cleanup_patch(self, capsys, tmp_path):
        ccache = tmp_path / "combined.ccache"
        ccache.write_bytes(b"dummy")
        profile = MagicMock(return_value=str(tmp_path / "profile"))
        exit_code, stdout, _ = run_main(
            self.FORGE_ARGV,
            capsys,
            parse_user_sid=self._parsed_sid(),
            forge_tickets=MagicMock(return_value=str(ccache)),
            create_firefox_profile=profile,
            cleanup=REAL,
        )
        temp_dir = profile.call_args[1]["temp_dir"]
        assert exit_code == 0
        assert "[*] Cleaned up." in stdout
        assert not os.path.isdir(temp_dir)
        assert not ccache.exists()

    def test_recovers_the_exit_code_from_argparse_system_exit(self, capsys):
        exit_code, stdout, stderr = run_main(["--domain", "d.local"], capsys)
        assert exit_code == 2
        assert stderr != ""
        assert "No auth mode specified" in stderr
        assert stdout == ""


class TestFailureOrdering:
    """C9: a boundary failure inside main()'s try reaches the user as one Error: line on
    stderr, carrying the exception's own exit code and no traceback unless --verbose.

    The failure is injected at create_firefox_profile, which sits inside main()'s try, so
    the finally runs and cleanup narrates before the message is printed.
    """

    FAILING_ARGV = [
        "--domain", "d.local",
        "--adssoacc-ntlm", "a" * 32, "--user", "admin",
        "--user-sid", "S-1-5-21-1-2-3-4",
    ]

    @staticmethod
    def _parsed_sid():
        return MagicMock(return_value=("S-1-5-21-1-2-3", 4))

    @staticmethod
    def _removing_cleanup(temp_dir, ccache_path=None):
        # Stands in for the real cleanup without draining the capture, so the test reads
        # the whole narration out of the streams run_main returns. It still removes
        # temp_dir, because tempfile.mkdtemp is never patched and the real directory would
        # otherwise outlive the test.
        shutil.rmtree(temp_dir, ignore_errors=True)

    def test_error_message_is_printed_after_the_cleanup_narration(self, capsys):
        at_cleanup = []

        def recording_cleanup(temp_dir, ccache_path=None):
            # readouterr() drains the buffer, so at_cleanup holds everything printed
            # before cleanup and the streams run_main returns afterwards hold only what
            # came after it. That split is the ordering proof. This removes temp_dir
            # itself because it replaces the real cleanup and mkdtemp is never patched.
            at_cleanup.append(capsys.readouterr())
            shutil.rmtree(temp_dir, ignore_errors=True)

        exit_code, stdout, stderr = run_main(
            self.FAILING_ARGV,
            capsys,
            parse_user_sid=self._parsed_sid(),
            create_firefox_profile=MagicMock(side_effect=RuntimeError("PROFILE-BOOM")),
            cleanup=recording_cleanup,
        )

        assert "Error: " not in at_cleanup[0].err  # nothing printed before cleanup ran
        assert "Error: " in stderr  # ... and printed after it
        assert "[*] Cleaned up." in stdout
        assert exit_code == 1

    def test_failing_boundary_exits_one_with_the_message_on_stderr(self, capsys):
        exit_code, stdout, stderr = run_main(
            self.FAILING_ARGV,
            capsys,
            parse_user_sid=self._parsed_sid(),
            create_firefox_profile=MagicMock(side_effect=RuntimeError("PROFILE-BOOM")),
            cleanup=self._removing_cleanup,
        )

        assert exit_code == 1
        assert stderr.startswith("Error: ")
        assert stdout != ""  # the progress narration still happened
        # The catch-all is the one clause that sees impacket's internals, which can carry
        # key material, so it must never echo the exception's own text.
        assert "PROFILE-BOOM" not in stderr

    @pytest.mark.parametrize(
        ("exc", "expected_code"),
        [
            (TicketError("the ticket is unreadable"), 3),
            (UsageError("--user-sid is not a SID"), 2),
        ],
    )
    def test_sso_error_becomes_its_exit_code_and_its_message(self, capsys, exc, expected_code):
        exit_code, _, stderr = run_main(
            self.FAILING_ARGV,
            capsys,
            parse_user_sid=self._parsed_sid(),
            create_firefox_profile=MagicMock(side_effect=exc),
            cleanup=self._removing_cleanup,
        )

        assert exit_code == expected_code
        # == not in: nothing else reached stderr — no traceback and no second marker.
        assert stderr == f"Error: {exc}\n"

    def test_keyboard_interrupt_exits_130_with_the_interrupted_message(self, capsys):
        exit_code, _, stderr = run_main(
            self.FAILING_ARGV,
            capsys,
            parse_user_sid=self._parsed_sid(),
            launch_firefox=MagicMock(side_effect=KeyboardInterrupt),
            cleanup=self._removing_cleanup,
        )

        assert exit_code == 130
        # interrupted_message()'s exact return, asserted literally so that a silent
        # change to either side is caught.
        assert stderr == "Error: interrupted before Firefox launched; nothing is still running\n"

    def test_verbose_appends_the_traceback_after_the_error_line(self, capsys):
        _, _, stderr = run_main(
            [*self.FAILING_ARGV, "--verbose"],
            capsys,
            parse_user_sid=self._parsed_sid(),
            create_firefox_profile=MagicMock(side_effect=RuntimeError("PROFILE-BOOM")),
            cleanup=self._removing_cleanup,
        )

        assert "Traceback (most recent call last)" in stderr
        assert stderr.index("Error: ") < stderr.index("Traceback (most recent call last)")
        assert "PROFILE-BOOM" in stderr  # under --verbose the detail is opted into

    def test_without_verbose_no_traceback_is_printed(self, capsys):
        _, _, stderr = run_main(
            self.FAILING_ARGV,
            capsys,
            parse_user_sid=self._parsed_sid(),
            create_firefox_profile=MagicMock(side_effect=RuntimeError("PROFILE-BOOM")),
            cleanup=self._removing_cleanup,
        )

        assert "Traceback (most recent call last)" not in stderr

    def test_failure_before_mkdtemp_narrates_no_cleanup(self, capsys):
        # find_firefox is injected so the subject stays main()'s guard rather than the real
        # find_firefox, which raises this same error itself. Nothing is created on this
        # path, so there is nothing for the test to remove either.
        cleanup_mock = MagicMock()

        exit_code, stdout, stderr = run_main(
            self.FAILING_ARGV,
            capsys,
            find_firefox=MagicMock(side_effect=LocalEnvironmentError("Firefox not found at /nope")),
            cleanup=cleanup_mock,
        )

        assert exit_code == 1
        assert stderr == "Error: Firefox not found at /nope\n"
        assert "[*] Cleaned up." not in stdout
        assert "Artifacts preserved" not in stdout
        assert "Traceback (most recent call last)" not in stderr
        # The guard's real subject: temp_dir is still None, so cleanup is never reached.
        # The absent narration above is only the symptom of this.
        cleanup_mock.assert_not_called()

    def test_mkdtemp_failure_exits_one_cleanly(self, capsys):
        # cli.py calls tempfile.mkdtemp(...) through the module attribute, and run_main
        # never patches tempfile, so replacing the module is what makes mkdtemp fail.
        fake_tempfile = MagicMock()
        fake_tempfile.mkdtemp.side_effect = OSError("No space left on device")

        exit_code, stdout, stderr = run_main(
            self.FAILING_ARGV,
            capsys,
            tempfile=fake_tempfile,
            cleanup=MagicMock(),
        )

        assert exit_code == 1
        assert stderr.startswith("Error: ")
        assert "[*] Cleaned up." not in stdout
        assert "Artifacts preserved" not in stdout
        assert "Traceback (most recent call last)" not in stderr
        # The catch-all handles this one, and it never echoes the exception's own text.
        assert "No space left on device" not in stderr

    def test_no_cleanup_narrates_nothing_when_nothing_was_created(self, capsys):
        # The guard is on temp_dir, not on args.no_cleanup: inverting the two nestings
        # prints "Artifacts preserved at: None".
        exit_code, stdout, _ = run_main(
            [*self.FAILING_ARGV, "--no-cleanup"],
            capsys,
            find_firefox=MagicMock(side_effect=LocalEnvironmentError("Firefox not found at /nope")),
            cleanup=MagicMock(),
        )

        assert exit_code == 1
        assert "Artifacts preserved at: None" not in stdout
        assert "Artifacts preserved" not in stdout

    def test_main_still_exits_one_when_the_explicit_firefox_path_is_missing(self, capsys, tmp_path):
        # find_firefox=REAL: only the genuine function raising through main() proves the
        # exit code and the exact stderr bytes a user sees for this condition.
        missing = tmp_path / "nonexistent"

        exit_code, stdout, stderr = run_main(
            [*self.FAILING_ARGV, "--firefox-path", str(missing)],
            capsys,
            find_firefox=REAL,
        )

        assert exit_code == 1
        # == not in: the frozen stderr, byte for byte, with nothing else on the stream.
        assert stderr == f"Error: Firefox not found at {missing}\n"
        assert "[*] Cleaned up." not in stdout
        assert "Traceback (most recent call last)" not in stderr

    def test_main_still_exits_one_when_firefox_is_not_on_path(self, capsys, monkeypatch):
        monkeypatch.setattr("seamless_sso_browser.launcher.shutil.which", lambda _: None)

        exit_code, _, stderr = run_main(self.FAILING_ARGV, capsys, find_firefox=REAL)

        assert exit_code == 1
        # The embedded newline is one message, not two prints: splitting it would reorder
        # the bytes a user sees.
        assert stderr == (
            "Error: Firefox not found on PATH.\n"
            "Install with: sudo apt install firefox-esr\n"
        )

    def test_argparse_still_exits_two_through_the_handler(self, capsys):
        # parse_args runs on main()'s first line, outside the try, and the chain has no
        # except SystemExit clause — so argparse's own exit 2 reaches the interpreter.
        exit_code, _, stderr = run_main(["--domain", "d.local"], capsys)

        assert exit_code == 2
        assert "No auth mode specified" in stderr
        assert "Error: " not in stderr  # parser.error output is argparse's, not ours


class TestProcessHarness:
    """Test cli.main()'s behaviour in a real process, via run_main_subprocess.

    Usage text is safe to assert on here. parse_args pins prog="seamless-sso-browser"
    explicitly, so argparse never consults sys.argv[0] and the usage line reads the same
    in this subprocess as it does in process, even though sys.argv[0] is "-c".
    """

    # Argv that parse_args rejects at exit 2: the SID is malformed, so the run never
    # reaches main()'s try at all.
    FAILING_ARGV = [
        "--domain", "d.local",
        "--adssoacc-ntlm", "a" * 32, "--user", "admin",
        "--user-sid", "NOT-A-SID",
    ]

    # The same run with a SID that parses, so a failure lands past the SID check.
    FAILING_ARGV_WITH_VALID_SID = [
        "--domain", "d.local",
        "--adssoacc-ntlm", "a" * 32, "--user", "admin",
        "--user-sid", "S-1-5-21-1111111111-2222222222-3333333333-1234",
    ]

    @staticmethod
    def _shim(tmp_path) -> str:
        """An executable stand-in for Firefox, never exec'd: every case fails before launch."""
        shim = tmp_path / "firefox"
        shim.touch()
        shim.chmod(shim.stat().st_mode | stat.S_IEXEC)
        return str(shim)

    @staticmethod
    def _run_with_a_failing_profile_write(argv: list[str]) -> subprocess.CompletedProcess[str]:
        """Run main() in a real process with create_firefox_profile raising.

        run_main_subprocess cannot inject a patch a fresh interpreter retains, and after
        S2-R2 no argv reaches main()'s catch-all on its own — which is the point of the
        stage. So the boundary failure is injected the way TestExitCodeSweepAcrossAProcess
        injects one: a -c script that patches the name on cli and then calls cli.main().
        create_firefox_profile is inside main()'s try and after mkdtemp, so the finally
        cleans up and narrates before the message is printed. The tickets are forged for
        real on the way there, which makes these the slowest cases in this class.
        """
        script = (
            "from seamless_sso_browser import cli\n"
            "def _raise(*a, **k):\n"
            "    raise RuntimeError('PROFILE-BOOM')\n"
            "cli.create_firefox_profile = _raise\n"
            "cli.main()\n"
        )
        return subprocess.run(
            [sys.executable, "-c", script, *argv],
            capture_output=True,
            text=True,
            timeout=30.0,
            check=False,
        )

    def test_help_exits_zero_with_output_on_stdout(self):
        result = run_main_subprocess(["--help"])
        assert result.returncode == 0
        assert result.stdout

    def test_help_usage_line_names_the_pinned_prog(self):
        result = run_main_subprocess(["--help"])
        assert "usage: seamless-sso-browser" in result.stdout

    def test_missing_auth_mode_exits_two_with_output_on_stderr(self):
        result = run_main_subprocess(["--domain", "d.local"])
        assert result.returncode == 2
        assert result.stderr

    def test_a_failing_run_prints_no_traceback_and_an_error_line(self, tmp_path):
        """C9 in a real process: the half run_main structurally cannot see.

        An in-process SystemExit never reaches the interpreter's traceback printer, so
        traceback absence is only observable here. The shim is never exec'd — the run
        fails at the injected profile write, long before launch.
        """
        result = self._run_with_a_failing_profile_write([
            *self.FAILING_ARGV_WITH_VALID_SID,
            "--firefox-path", self._shim(tmp_path),
        ])

        # An unhandled exception also exits 1 in CPython, so the code alone proves nothing
        # here; the traceback's absence and the Error: line are what this asserts.
        assert result.returncode == 1
        assert "Traceback (most recent call last)" not in result.stderr
        assert "Error: " in result.stderr
        assert "[*] Cleaned up." in result.stdout

    def test_missing_auth_mode_still_exits_two_with_no_traceback(self):
        """main()'s except chain is narrow enough that argparse's exit 2 passes through."""
        result = run_main_subprocess(["--domain", "d.local"])

        assert result.returncode == 2
        assert "Traceback (most recent call last)" not in result.stderr

    def test_verbose_prints_the_traceback_after_the_error_line(self, tmp_path):
        """The positive control that keeps every no-traceback assertion honest.

        Asserting a traceback is absent passes just as happily when the harness is blind,
        when the invocation never ran, or when stderr was never captured. This asserts one
        is present, on the same failing path through the same harness, so the absence
        asserted elsewhere is a property of main() rather than of the test.
        """
        argv = [*self.FAILING_ARGV_WITH_VALID_SID, "--firefox-path", self._shim(tmp_path)]
        verbose_result = self._run_with_a_failing_profile_write([*argv, "--verbose"])
        plain_result = self._run_with_a_failing_profile_write(argv)

        assert verbose_result.returncode == 1
        assert "Error: " in verbose_result.stderr
        assert "Traceback (most recent call last)" in verbose_result.stderr
        assert verbose_result.stderr.index("Error: ") < verbose_result.stderr.index(
            "Traceback (most recent call last)"
        )
        # The traceback is diagnostic output, so it belongs on stderr with the error line.
        assert "Traceback (most recent call last)" not in verbose_result.stdout
        # Opted in, the user gets the detail the catch-all withholds by default.
        assert "PROFILE-BOOM" in verbose_result.stderr
        # --verbose adds output; it does not change the outcome.
        assert verbose_result.returncode == plain_result.returncode

    def test_the_unexpected_failure_message_withholds_the_exception_text(self, tmp_path):
        """The catch-all's opsec property, in the bytes a real process wrote.

        The injected exception is RuntimeError("PROFILE-BOOM"), so the exception's own
        message carries a string nothing else would print. This is a red-team tool whose
        terminal scrollback outlives the process, and the catch-all is the one clause that
        can see impacket's internals, so the default message must not repeat it.
        """
        result = self._run_with_a_failing_profile_write([
            *self.FAILING_ARGV_WITH_VALID_SID,
            "--firefox-path", self._shim(tmp_path),
        ])

        assert result.returncode == 1
        assert "Error: unexpected RuntimeError; re-run with --verbose for the traceback" in (
            result.stderr
        )
        assert "PROFILE-BOOM" not in result.stderr
        assert "Traceback (most recent call last)" not in result.stderr

    def test_a_malformed_sid_exits_two_with_the_pinned_message_and_no_traceback(self, tmp_path):
        result = run_main_subprocess([
            *self.FAILING_ARGV, "--firefox-path", self._shim(tmp_path),
        ])

        assert result.returncode == 2
        assert sid_format_message(got="NOT-A-SID") in result.stderr
        assert "Traceback (most recent call last)" not in result.stderr
        # parser.error output is argparse's own, so the handler adds no Error: line.
        assert "Error: " not in result.stderr
        # Rejected before mkdtemp: nothing was created, so nothing narrates.
        assert result.stdout == ""

    def test_a_missing_firefox_path_exits_one_with_the_baseline_stderr(self, tmp_path):
        """The frozen Firefox-not-found surface, through a real process.

        The SID here is valid so the run fails on Firefox by intent rather than by
        statement order: find_firefox runs before parse_user_sid, so an invalid SID would
        make this pass for the wrong reason if validation ever moved earlier.
        """
        missing = tmp_path / "nonexistent"

        result = run_main_subprocess([
            *self.FAILING_ARGV_WITH_VALID_SID,
            "--firefox-path", str(missing),
        ])

        assert result.returncode == 1
        # ==, not in: exit 1 with exactly these bytes is the frozen surface, and an empty
        # stdout is the other half of "created nothing, narrates nothing" — the failure
        # happens before mkdtemp.
        assert result.stderr == f"Error: Firefox not found at {missing}\n"
        assert result.stdout == ""
        assert "Traceback (most recent call last)" not in result.stderr

    def test_argparse_still_exits_two_without_a_traceback(self):
        """The frozen exit-2 surface, on a parser.error path that reaches it a second way.

        parse_args runs before main()'s try, so argparse's SystemExit is outside the reach
        of the except chain twice over — SystemExit is not an Exception either. What this
        pins is the observable surface: still 2, still argparse's own wording, and no
        Error: line claiming the handler produced it. --target routes through
        _resolve_target, a different parser.error call site than the missing-auth-mode
        case above.
        """
        result = run_main_subprocess(["--domain", "d.local", "--target", "not-a-preset"])

        assert result.returncode == 2
        assert "Traceback (most recent call last)" not in result.stderr
        assert "Error: " not in result.stderr  # parser.error output is argparse's, not ours


class TestExitCodeSweepAcrossAProcess:
    """The errors.py exit_code <-> main()'s except chain correspondence, all six
    subclasses at once, proven in a real process.

    The other classes here reach main() through a boundary that genuinely raises, which
    covers only some of the six; KdcUnreachableError, KdcProtocolError and the base
    SsoError have no such call site. So this builds its own -c script that monkeypatches
    parse_user_sid to raise each type directly, rather than going through run_main or
    run_main_subprocess: neither can inject a patch that a real process retains.
    """

    ARGV = [
        "--domain", "d.local",
        "--adssoacc-ntlm", "a" * 32, "--user", "admin",
        "--user-sid", "S-1-5-21-1111111111-2222222222-3333333333-1234",
    ]

    @pytest.mark.parametrize(
        ("ctor", "message", "expected_code"),
        [
            ("SsoError", "BASE-BOOM", 1),
            ("UsageError", "USAGE-BOOM", 2),
            ("TicketError", "TICKET-BOOM", 3),
            ("KdcUnreachableError", "KDC-UNREACHABLE-BOOM", 4),
            ("KdcProtocolError", "KDC-PROTOCOL-BOOM", 5),
            ("LocalEnvironmentError", "ENV-BOOM", 1),
        ],
    )
    def test_each_sso_error_subclass_maps_to_its_own_exit_code(
        self, tmp_path, ctor, message, expected_code
    ):
        shim = tmp_path / "firefox"
        shim.touch()
        shim.chmod(shim.stat().st_mode | stat.S_IEXEC)

        script = (
            "from seamless_sso_browser import cli\n"
            "from seamless_sso_browser.errors import (\n"
            "    SsoError, UsageError, TicketError, KdcUnreachableError,\n"
            "    KdcProtocolError, LocalEnvironmentError,\n"
            ")\n"
            "def _raise(*a, **k):\n"
            f"    raise {ctor}({message!r})\n"
            "cli.parse_user_sid = _raise\n"
            "cli.main()\n"
        )

        result = subprocess.run(
            [sys.executable, "-c", script, *self.ARGV, "--firefox-path", str(shim)],
            capture_output=True,
            text=True,
            timeout=30.0,
        )

        assert result.returncode == expected_code
        # ==, not in: exit code and message body only, nothing else on stderr.
        assert result.stderr == f"Error: {message}\n"
        assert "Traceback (most recent call last)" not in result.stderr


class TestKdcErrorRendering:
    """C2.1/C2.2/C2.3/C2.4: a KDC failure reaches the operator as one Error: line at either
    wrapped call site -- exit 4 for an unreachable DC and exit 5 for a protocol error,
    the one register-split row worded for the run's own IdP, the neutral rows identical
    in both, an unmapped code still clean -- with no traceback unless --verbose asks and
    no credential on either stream."""

    AZURE_ARGV = [
        "--domain", "test.local", "--dc-ip", "127.0.0.1",
        "--user", "admin", "--password", "Password1",
    ]
    OKTA_ARGV = [*AZURE_ARGV, "--idp", "okta", "--okta-org", "acme"]

    # By name out of impacket's own table, never as a number.
    SPN_UNKNOWN = constants.ErrorCodes.KDC_ERR_S_PRINCIPAL_UNKNOWN.value
    PREAUTH_FAILED = constants.ErrorCodes.KDC_ERR_PREAUTH_FAILED.value
    WRONG_REALM = constants.ErrorCodes.KDC_ERR_WRONG_REALM.value
    SKEW = constants.ErrorCodes.KRB_AP_ERR_SKEW.value

    # The four rows errors.py maps to one neutral string each. KDC_ERR_S_PRINCIPAL_UNKNOWN
    # is deliberately absent: it is the only row whose wording differs by register.
    NEUTRAL_ROW_NAMES = (
        "KDC_ERR_WRONG_REALM",
        "KDC_ERR_PREAUTH_FAILED",
        "KDC_ERR_C_PRINCIPAL_UNKNOWN",
        "KRB_AP_ERR_SKEW",
    )

    @staticmethod
    def _run_with_kdc_code(
        argv: list[str], capsys, code: int, *, at: str = "tgs_from_credentials"
    ) -> tuple[int, str, str]:
        """Run main() with the KDC answering `code` at one of the two wrapped call sites.

        The patch value replaces the object, so the failure is injected as a MagicMock
        whose side_effect is a raw impacket KerberosError. kerberos.py's own wrap sites
        never run on this seam, so what renders here is cli.py's boundary and nothing else.
        """
        return run_main(
            argv, capsys, **{at: MagicMock(side_effect=KerberosError(error=code))}
        )

    def test_the_azure_register_names_the_azure_sso_account(self, capsys):
        exit_code, _, stderr = run_main(
            self.AZURE_ARGV,
            capsys,
            tgs_from_credentials=MagicMock(side_effect=KerberosError(error=self.SPN_UNKNOWN)),
        )

        assert exit_code == 5
        assert "AZUREADSSOACC$" in stderr

    def test_the_okta_register_names_the_okta_dsso_spn(self, capsys):
        # KDC_ERR_S_PRINCIPAL_UNKNOWN is the one row whose wording differs between the
        # registers, so both directions get a test.
        exit_code, _, stderr = run_main(
            self.OKTA_ARGV,
            capsys,
            tgs_from_credentials=MagicMock(side_effect=KerberosError(error=self.SPN_UNKNOWN)),
        )

        assert exit_code == 5
        assert "HTTP/acme.kerberos.okta.com" in stderr
        assert "AZUREADSSOACC$" not in stderr

    def test_an_unreachable_kdc_exits_four_through_main(self, capsys):
        # Injected a level below run_main's **patches, which name attributes on
        # seamless_sso_browser.cli only. A raw OSError is translated in kerberos.py,
        # where the address is known, and nowhere at cli.py's boundary — so this runs
        # the real tgs_from_credentials and proves the whole path through it.
        with patch(
            "seamless_sso_browser.kerberos.getKerberosTGT",
            side_effect=OSError(
                "Connection error (127.0.0.1:88)",
                ConnectionRefusedError(errno.ECONNREFUSED, "Connection refused"),
            ),
        ):
            exit_code, _, stderr = run_main(
                self.AZURE_ARGV, capsys, tgs_from_credentials=REAL
            )

        assert exit_code == 4
        assert "127.0.0.1:88" in stderr
        assert "--dc-ip" in stderr

    def test_no_traceback_reaches_stderr_on_the_kdc_path(self, capsys):
        # The control on the funnel: a later task rewords this message without letting
        # a traceback back onto stderr.
        _, _, stderr = run_main(
            self.AZURE_ARGV,
            capsys,
            tgs_from_credentials=MagicMock(side_effect=KerberosError(error=self.SPN_UNKNOWN)),
        )

        assert "Traceback (most recent call last)" not in stderr
        assert stderr.startswith("Error: ")

    def test_the_password_never_reaches_either_stream(self, capsys):
        # PREAUTH_FAILED is the row a wrong credential produces, impacket's internals
        # hold key material, and the terminal scrollback outlives the process.
        _, stdout, stderr = run_main(
            self.AZURE_ARGV,
            capsys,
            tgs_from_credentials=MagicMock(side_effect=KerberosError(error=self.PREAUTH_FAILED)),
        )

        assert "Password1" not in stdout
        assert "Password1" not in stderr

    @pytest.mark.parametrize("code_name", NEUTRAL_ROW_NAMES)
    def test_every_neutral_row_renders_the_same_text_in_both_registers(self, code_name, capsys):
        # Four of the five mapped rows are register-independent, and this is what keeps
        # them so: the register split belongs to KDC_ERR_S_PRINCIPAL_UNKNOWN alone.
        code = constants.ErrorCodes[code_name].value

        azure_exit, _, azure_stderr = self._run_with_kdc_code(self.AZURE_ARGV, capsys, code)
        okta_exit, _, okta_stderr = self._run_with_kdc_code(self.OKTA_ARGV, capsys, code)

        assert azure_exit == 5
        assert okta_exit == 5
        assert azure_stderr == okta_stderr

    def test_the_skew_row_names_the_clock_and_the_fix(self, capsys):
        # The row an operator hits most often, and the one the README cross-references.
        _, _, stderr = self._run_with_kdc_code(self.AZURE_ARGV, capsys, self.SKEW)

        assert "clock" in stderr.lower()
        assert "5 minutes" in stderr

    def test_an_unmapped_code_exits_five_with_a_clean_message(self, capsys):
        # A code no impacket table knows. The default branch cannot raise: a KeyError
        # here would be a traceback in the middle of error handling.
        exit_code, _, stderr = self._run_with_kdc_code(self.AZURE_ARGV, capsys, 9999)

        assert exit_code == 5
        assert "Traceback (most recent call last)" not in stderr
        assert "9999" in stderr

    @pytest.mark.parametrize(
        ("argv", "args_idp"),
        [(AZURE_ARGV, errors.IDP_AZURE), (OKTA_ARGV, errors.IDP_OKTA)],
    )
    def test_neither_register_names_the_other_vendors_product(self, argv, args_idp, capsys):
        # TestOpsecMessages reads stdout only, so the register contract's negative half
        # is guarded here for stderr. The lists come from forbidden_terms, never restated.
        exit_code, _, stderr = self._run_with_kdc_code(argv, capsys, self.SPN_UNKNOWN)

        assert exit_code == 5
        for term in errors.forbidden_terms(args_idp):
            assert term not in stderr

    def test_the_tgt_path_renders_the_same_way(self, tmp_path, capsys):
        # Two wrapped call sites, two tests. --tgt checks the ticket kind before it calls
        # the KDC, so this one needs a real TGT-shaped ticket on disk.
        tgt_path = str(tmp_path / "tgt.ccache")
        make_dummy_ccache(tgt_path, "krbtgt/TEST.LOCAL")
        azure_argv = ["--domain", "test.local", "--dc-ip", "127.0.0.1", "--tgt", tgt_path]
        okta_argv = [*azure_argv, "--idp", "okta", "--okta-org", "acme"]

        azure_exit, _, azure_stderr = self._run_with_kdc_code(
            azure_argv, capsys, self.SPN_UNKNOWN, at="tgs_from_tgt"
        )
        okta_exit, _, okta_stderr = self._run_with_kdc_code(
            okta_argv, capsys, self.SPN_UNKNOWN, at="tgs_from_tgt"
        )

        assert azure_exit == 5
        assert "AZUREADSSOACC$" in azure_stderr
        assert okta_exit == 5
        assert "HTTP/acme.kerberos.okta.com" in okta_stderr
        assert "AZUREADSSOACC$" not in okta_stderr

    def test_the_code_and_the_code_name_survive_the_rerender(self, capsys):
        # Drop code_name on the way into kdc_error_message and this row falls to the
        # default branch, which names a number where the mapped row names the flag to
        # fix. The numeric code's own survival is what the unmapped-code test reads.
        exit_code, _, stderr = self._run_with_kdc_code(
            self.AZURE_ARGV, capsys, self.WRONG_REALM
        )

        assert exit_code == 5
        assert "--domain" in stderr

    def test_verbose_still_shows_impackets_traceback_after_the_error_line(self, capsys):
        # The positive control every no-traceback assertion rests on: --verbose does print
        # one, and chaining with "from exc" is what puts impacket's own frames in it.
        _, _, stderr = self._run_with_kdc_code(
            [*self.AZURE_ARGV, "--verbose"], capsys, self.WRONG_REALM
        )

        assert "Error: " in stderr
        assert "Traceback (most recent call last)" in stderr
        assert "KerberosError" in stderr
        assert stderr.index("Error: ") < stderr.index("Traceback (most recent call last)")

    @pytest.mark.parametrize("extra_argv", [[], ["--verbose"]])
    def test_the_password_never_reaches_either_stream_with_or_without_verbose(
        self, extra_argv, capsys
    ):
        # KDC_ERR_PREAUTH_FAILED is the row a wrong credential produces, and --verbose
        # prints a traceback through impacket's frames. The scrollback outlives the run.
        marker = "MARKER-Password-2f9c"
        argv = [
            "--domain", "test.local", "--dc-ip", "127.0.0.1",
            "--user", "admin", "--password", marker, *extra_argv,
        ]

        exit_code, stdout, stderr = self._run_with_kdc_code(argv, capsys, self.PREAUTH_FAILED)

        assert exit_code == 5
        assert marker not in stdout
        assert marker not in stderr


class TestKdcWaitNotice:
    # An unreachable DC takes about a minute to fail, and G1 sat silent for all of it with
    # "[*] Requesting TGT from DC ..." as the last line on screen -- which reads as a hang
    # and gets answered with Ctrl+C. One notice printed after each round-trip announcement
    # says the wait is expected (C2.5). Every assertion reads the text off
    # cli._KDC_WAIT_NOTICE rather than restating it, so these tests pin the stream and the
    # placement while the wording stays editable in one place.
    CREDS_ARGV = [
        "--domain", "test.local", "--dc-ip", "10.0.0.1",
        "--user", "admin", "--password", "Password1",
    ]

    @staticmethod
    def _tgt_argv(tmp_path):
        # The --tgt branch checks the ticket kind before it announces the request, so a
        # service ticket would exit 3 before the notice ever printed.
        tgt_path = str(tmp_path / "tgt.ccache")
        make_dummy_ccache(tgt_path, "krbtgt/TEST.LOCAL")
        return ["--domain", "test.local", "--dc-ip", "10.0.0.1", "--tgt", tgt_path]

    def test_the_credential_path_announces_the_wait_before_the_round_trip(self, capsys):
        exit_code, stdout, _ = run_main(self.CREDS_ARGV, capsys)

        assert exit_code == 0
        assert cli._KDC_WAIT_NOTICE in stdout
        assert stdout.index(cli._KDC_WAIT_NOTICE) > stdout.index("[*] Requesting TGT from DC")

    def test_the_tgt_path_announces_the_wait(self, tmp_path, capsys):
        exit_code, stdout, _ = run_main(self._tgt_argv(tmp_path), capsys)

        assert exit_code == 0
        assert cli._KDC_WAIT_NOTICE in stdout
        assert stdout.index(cli._KDC_WAIT_NOTICE) > stdout.index("[*] Requesting TGS from DC")

    def test_the_okta_tgt_path_announces_the_same_wait(self, tmp_path, capsys):
        # The announcement above this line is register-branched; the notice is not. Putting
        # it after the branch is what lets one line serve both registers.
        argv = [*self._tgt_argv(tmp_path), "--idp", "okta", "--okta-org", "acme"]

        exit_code, stdout, _ = run_main(argv, capsys)

        assert exit_code == 0
        assert cli._KDC_WAIT_NOTICE in stdout
        assert stdout.index(cli._KDC_WAIT_NOTICE) > stdout.index("[*] Requesting TGS from DC")

    def test_the_notice_names_a_duration_and_the_dc(self):
        # A notice that says only "please wait" does not tell the operator whether sixty
        # seconds is normal, which is the whole content of C2.5.
        assert "minute" in cli._KDC_WAIT_NOTICE
        assert "DC" in cli._KDC_WAIT_NOTICE

    def test_the_notice_names_no_vendor_product(self):
        # One line serves both registers, so it has to survive the neutral term list.
        for term in errors.forbidden_terms(None):
            assert term not in cli._KDC_WAIT_NOTICE

    def test_the_notice_goes_to_stdout_and_not_to_stderr(self, capsys):
        # All narration is stdout; only errors and warnings are stderr.
        exit_code, stdout, stderr = run_main(self.CREDS_ARGV, capsys)

        assert exit_code == 0
        assert cli._KDC_WAIT_NOTICE in stdout
        assert cli._KDC_WAIT_NOTICE not in stderr


class TestLaunchFailureThroughMain:
    # C5 end to end. A
    # --firefox-path that exists but cannot be executed used to be accepted, so the run
    # narrated full success and exited 0 after promising no password prompt would appear;
    # and when Popen failed at exec time, the OSError landed in main()'s catch-all as
    # "unexpected PermissionError", which named neither the binary nor what was wrong with
    # it. Both paths now exit 1 with a message naming the binary. A real ccache is what
    # carries each run as far as the launch stage.
    AZURE_SPN = "HTTP/autologon.microsoftazuread-sso.com@TEST.LOCAL"

    def test_a_non_executable_firefox_exits_one_before_the_banner(self, tmp_path, capsys):
        shim = tmp_path / "firefox"
        shim.write_text("#!/bin/sh\n")
        shim.chmod(0o644)
        ccache = str(tmp_path / "good.ccache")
        make_dummy_ccache(ccache, self.AZURE_SPN)

        exit_code, stdout, stderr = run_main(
            ["--domain", "test.local", "--ccache", ccache, "--firefox-path", str(shim)],
            capsys,
            find_firefox=REAL,
        )

        assert exit_code == 1
        assert "Error: " in stderr
        assert str(shim) in stderr
        # Caught at the gate: the launch banner must never have printed.
        assert "Launching Firefox" not in stdout

    def test_a_popen_failure_exits_one_with_a_clean_message(self, tmp_path, capsys):
        # find_firefox stays patched, so "/usr/bin/firefox" is the path launch_firefox is
        # handed and the one the message has to name. create_firefox_profile and
        # create_krb5_conf stay patched too, and verbose=False means neither is opened.
        ccache = str(tmp_path / "good.ccache")
        make_dummy_ccache(ccache, self.AZURE_SPN)

        with patch(
            "seamless_sso_browser.launcher.subprocess.Popen",
            side_effect=PermissionError(13, "Permission denied"),
        ):
            exit_code, _, stderr = run_main(
                ["--domain", "test.local", "--ccache", ccache],
                capsys,
                launch_firefox=REAL,
            )

        assert exit_code == 1
        assert "Error: " in stderr
        assert "/usr/bin/firefox" in stderr
        # The catch-all's wording was the defect: it named the exception class and nothing
        # the user could act on, so landing there again is the regression to catch.
        assert "unexpected" not in stderr


class TestUnwritablePathsThroughMain:
    # C3.2. A
    # read-only filesystem, a full disk or a permission problem in the temp directory
    # makes create_firefox_profile or create_krb5_conf raise OSError, and that lands in
    # main()'s catch-all as "unexpected PermissionError". Exit 1 is already right; the
    # message is not, because it names an exception class instead of which artefact could
    # not be written and why, so the operator cannot tell a full disk from a permission
    # problem. Each run drives --ccache so it reaches the profile stage without a KDC, and
    # tempfile.mkdtemp is unpatched, so temp_dir is a real path the fixed message can name.
    AZURE_SPN = "HTTP/autologon.microsoftazuread-sso.com@TEST.LOCAL"

    def test_a_profile_write_failure_names_the_profile_and_exits_one(self, tmp_path, capsys):
        ccache = str(tmp_path / "good.ccache")
        make_dummy_ccache(ccache, self.AZURE_SPN)

        exit_code, _, stderr = run_main(
            ["--domain", "test.local", "--ccache", ccache],
            capsys,
            create_firefox_profile=MagicMock(
                side_effect=PermissionError(errno.EACCES, "Permission denied"),
            ),
        )

        assert exit_code == 1
        assert "Error: " in stderr
        assert "the Firefox profile" in stderr
        # The catch-all's wording is the defect: it names the exception class and
        # nothing the operator can act on.
        assert "unexpected" not in stderr

    def test_a_krb5_conf_write_failure_names_krb5_conf_and_exits_one(self, tmp_path, capsys):
        # ENOSPC rather than EACCES, so the two write failures do not prove the same errno
        # branch twice: the fixed message has to tell a full filesystem from a permission
        # problem.
        ccache = str(tmp_path / "good.ccache")
        make_dummy_ccache(ccache, self.AZURE_SPN)

        exit_code, _, stderr = run_main(
            ["--domain", "test.local", "--ccache", ccache],
            capsys,
            create_krb5_conf=MagicMock(
                side_effect=OSError(errno.ENOSPC, "No space left on device"),
            ),
        )

        assert exit_code == 1
        assert "Error: " in stderr
        assert "krb5.conf" in stderr
        assert "unexpected" not in stderr

    def test_a_write_failure_still_cleans_up_and_prints_one_error_line(self, tmp_path, capsys):
        # The ordering half of the handler contract on this path: cleanup narrates, then the
        # error line prints last. capsys splits the streams, so the interleaving itself is
        # not observable here -- cleanup having run and exactly one error line surviving on
        # stderr are the observable form of it.
        ccache = str(tmp_path / "good.ccache")
        make_dummy_ccache(ccache, self.AZURE_SPN)
        cleanup_mock = MagicMock()

        exit_code, stdout, stderr = run_main(
            ["--domain", "test.local", "--ccache", ccache],
            capsys,
            create_krb5_conf=MagicMock(
                side_effect=PermissionError(errno.EACCES, "Permission denied"),
            ),
            cleanup=cleanup_mock,
        )

        assert exit_code == 1
        assert cleanup_mock.called
        assert "[*] Cleaned up." in stdout
        assert stderr.count("Error: ") == 1
        assert "Traceback (most recent call last)" not in stderr
        assert "krb5.conf" in stderr
        assert "unexpected" not in stderr

    @pytest.mark.parametrize(
        "code, expected_reason",
        [
            (errno.EACCES, errors.PATH_REASON_PERMISSION),
            (errno.EPERM, errors.PATH_REASON_PERMISSION),
            (errno.EROFS, errors.PATH_REASON_READ_ONLY),
            (errno.ENOSPC, errors.PATH_REASON_NO_SPACE),
            (errno.EMFILE, errors.PATH_REASON_OTHER),
        ],
    )
    def test_the_write_failure_reason_follows_the_errno(
        self, code, expected_reason, tmp_path, capsys
    ):
        # EMFILE is the unmapped row: an errno nobody enumerated still has to render one of
        # the four reasons rather than raise in the middle of error handling.
        ccache = str(tmp_path / "good.ccache")
        make_dummy_ccache(ccache, self.AZURE_SPN)

        exit_code, _, stderr = run_main(
            ["--domain", "test.local", "--ccache", ccache],
            capsys,
            create_firefox_profile=MagicMock(
                side_effect=OSError(code, "whatever the OS said"),
            ),
        )

        assert exit_code == 1
        assert expected_reason in stderr

    def test_the_write_failure_message_names_the_real_temp_dir(self, tmp_path, capsys):
        # run_main leaves tempfile.mkdtemp alone, so main() creates its own sso- directory
        # and the message has to name that. The injected PermissionError carries no
        # filename, so a message built from err.filename would print None here instead of
        # the directory whose filesystem the operator can act on.
        ccache = str(tmp_path / "good.ccache")
        make_dummy_ccache(ccache, self.AZURE_SPN)

        exit_code, _, stderr = run_main(
            ["--domain", "test.local", "--ccache", ccache],
            capsys,
            create_firefox_profile=MagicMock(
                side_effect=PermissionError(errno.EACCES, "Permission denied"),
            ),
        )

        assert exit_code == 1
        assert tempfile.gettempdir() in stderr
        assert "sso-" in stderr
        assert "None" not in stderr

    def test_the_message_carries_no_os_text(self, tmp_path, capsys):
        # No OS-provided string is interpolated into a user-facing message in this project:
        # the reason is one of the four constants, chosen from errno.
        ccache = str(tmp_path / "good.ccache")
        make_dummy_ccache(ccache, self.AZURE_SPN)

        exit_code, _, stderr = run_main(
            ["--domain", "test.local", "--ccache", ccache],
            capsys,
            create_krb5_conf=MagicMock(
                side_effect=OSError(errno.EROFS, "Read-only file system"),
            ),
        )

        assert exit_code == 1
        assert "Read-only file system" not in stderr
        assert errors.PATH_REASON_READ_ONLY in stderr

    def test_a_ticket_error_from_the_write_reaches_main_unchanged(self, tmp_path, capsys):
        # TicketError is a ValueError, not an OSError, so the wrap around the krb5.conf
        # write must let it past untouched rather than restating it as exit 1.
        ccache = str(tmp_path / "good.ccache")
        make_dummy_ccache(ccache, self.AZURE_SPN)

        exit_code, _, stderr = run_main(
            ["--domain", "test.local", "--ccache", ccache],
            capsys,
            create_krb5_conf=MagicMock(side_effect=TicketError("a marker message")),
        )

        assert exit_code == 3
        assert "a marker message" in stderr

    def test_a_kdc_unreachable_error_beside_the_wraps_reaches_main_unchanged(
        self, tmp_path, capsys
    ):
        # KdcUnreachableError IS an OSError, so it is the error the two "except OSError"
        # clauses could swallow. Each clause covers one call into profile.py and nothing
        # else; launch_firefox sits outside both of them, so this test fails only if a try
        # is widened far enough downwards to cover the launch, which would report this as
        # exit 1 instead of exit 4.
        ccache = str(tmp_path / "good.ccache")
        make_dummy_ccache(ccache, self.AZURE_SPN)

        exit_code, _, stderr = run_main(
            ["--domain", "test.local", "--ccache", ccache],
            capsys,
            launch_firefox=MagicMock(side_effect=KdcUnreachableError("another marker")),
        )

        assert exit_code == 4
        assert "another marker" in stderr


class TestInterruptContract:
    # C4 -- the interrupt half of the handler contract, which until now rested on
    # inspection even though the README documents the exit code. The mechanism already
    # exists; these tests are the regression lock on it, so they pass from the moment
    # they are correct.
    #
    # The asymmetry between the two halves is deliberate: 130 means the run was aborted
    # before the session started, 0 means the session ran and ended.
    #
    #   Ctrl+C before Firefox launched  ->  130, one clean line, cleanup narrated
    #   Ctrl+C while Firefox is running ->  0, because launch_firefox's own SIGINT
    #                                       handler terminates the child and nothing
    #                                       propagates (pinned in tests/test_launcher.py)
    #
    # Each run drives --ccache so it reaches the profile stage without a KDC, matching
    # the class above. KeyboardInterrupt is a BaseException, so neither of the two
    # "except OSError" wraps around the profile writes intercepts it, and run_main
    # catches SystemExit only -- main()'s own first clause is what turns it into
    # sys.exit(130), which is why run_main returns rather than propagating.
    AZURE_SPN = "HTTP/autologon.microsoftazuread-sso.com@TEST.LOCAL"

    @pytest.mark.parametrize(
        "boundary",
        ["create_firefox_profile", "create_krb5_conf"],
    )
    def test_an_interrupt_before_launch_exits_130_with_one_clean_line(
        self, boundary, tmp_path, capsys
    ):
        # Two boundaries rather than one, so the test pins main()'s except clause rather
        # than the behaviour of a single mock: the second row is the same contract at a
        # later point in the run.
        ccache = str(tmp_path / "good.ccache")
        make_dummy_ccache(ccache, self.AZURE_SPN)

        exit_code, _, stderr = run_main(
            ["--domain", "test.local", "--ccache", ccache],
            capsys,
            **{boundary: MagicMock(side_effect=KeyboardInterrupt())},
        )

        assert exit_code == errors.EXIT_INTERRUPTED
        # The strong form, and it holds: no warning fires on this argv, so main() prints
        # exactly this one line. An extra line here would be a finding, not a reason to
        # weaken the assertion.
        assert stderr == f"Error: {errors.interrupted_message()}\n"
        assert "Traceback (most recent call last)" not in stderr

    def test_an_interrupt_before_launch_still_cleans_up(self, tmp_path, capsys):
        # What this test cannot assert, and why: the contract is that cleanup narrates
        # first and the error line prints last, so the error is the last thing the user
        # reads -- but capsys splits stdout from stderr, so that interleaving is not
        # observable here, and run_main_subprocess splits them too. The two observable
        # facts are what the ordering takes the shape of in a test: cleanup ran and
        # narrated on stdout, and the single "Error: " line landed on stderr. The
        # ordering itself is structural rather than asserted -- main()'s except clauses
        # only record, the finally cleans up and narrates, and the "Error: " line prints
        # after the try/finally (cli.py:800-828). Do not add an assertion that claims
        # more than the harness can see.
        ccache = str(tmp_path / "good.ccache")
        make_dummy_ccache(ccache, self.AZURE_SPN)
        cleanup_mock = MagicMock()

        exit_code, stdout, stderr = run_main(
            ["--domain", "test.local", "--ccache", ccache],
            capsys,
            create_firefox_profile=MagicMock(side_effect=KeyboardInterrupt()),
            cleanup=cleanup_mock,
        )

        assert exit_code == errors.EXIT_INTERRUPTED
        assert cleanup_mock.called
        assert "[*] Cleaned up." in stdout
        assert stderr == f"Error: {errors.interrupted_message()}\n"

    def test_a_verbose_interrupt_prints_the_traceback_after_the_error_line(
        self, tmp_path, capsys
    ):
        # The positive control for the two tests above, and not optional: an asserted
        # absence of a traceback passes just as happily against a harness that cannot see
        # tracebacks at all. --verbose is the one path that prints one, so this is what
        # proves the absence assertions are measuring something.
        ccache = str(tmp_path / "good.ccache")
        make_dummy_ccache(ccache, self.AZURE_SPN)

        exit_code, _, stderr = run_main(
            ["--domain", "test.local", "--ccache", ccache, "--verbose"],
            capsys,
            create_firefox_profile=MagicMock(side_effect=KeyboardInterrupt()),
        )

        assert exit_code == errors.EXIT_INTERRUPTED
        assert f"Error: {errors.interrupted_message()}" in stderr
        assert "Traceback (most recent call last)" in stderr
        # Both are on stderr, so their relative order is observable here, unlike the
        # stdout/stderr interleaving the cleanup test above cannot assert. The error line
        # comes first and the traceback follows it, so the message a user reads is not
        # buried under the trace.
        assert stderr.index("Error: ") < stderr.index("Traceback (most recent call last)")


class TestTracebackContractAcrossAProcess:
    """S2-R26/F2.3: one clean line without --verbose, the traceback after it with --verbose
    -- pinned in both directions on one real argv path per exit-code class.

    Both directions or neither counts. "Traceback (most recent call last)" not in stderr
    passes just as happily when the command never ran, when stderr was never captured, or
    when the harness cannot see a traceback at all, so every absence here is paired with
    the presence assertion on the same path through the same harness. That pairing is what
    makes the absence a property of main() rather than of the test.

    A real process is the only place either half is observable. run_main catches
    SystemExit in process, and a SystemExit never reaches the interpreter's traceback
    printer, so no traceback prints there whether or not main() would have printed one:
    the in-process layer structurally cannot tell a working handler from a blind harness.
    Every run here goes through run_main_subprocess for that reason.

    Four paths, one per exit-code class, each reached from argv alone with nothing patched
    and nothing injected: a --ccache that is not there (3), a KDC on loopback with nothing
    listening (4), a --firefox-path that exists and cannot be executed (1), and argparse's
    own rejection of a malformed key (2), which breaks the symmetry on purpose.
    """

    # A ccache that parses, so the exit-1 case's argv is well formed. find_firefox runs
    # ahead of the ticket work, so that case never reads it.
    AZURE_SPN = "HTTP/autologon.microsoftazuread-sso.com@TEST.LOCAL"
    # The kind --tgt requires: a service ticket would exit 3 before the KDC is dialled.
    TGT_SPN = "krbtgt/TEST.LOCAL"

    # Loopback with nothing listening on 88 is refused at once -- no DNS lookup, no
    # timeout, and no address off this host. impacket dials 88 from its own sendReceive
    # default; kerberos._KDC_PORT mirrors it and is what the message is built from, so the
    # port is read off that constant rather than restated here.
    DC_IP = "127.0.0.1"
    KDC_ADDRESS = f"{DC_IP}:{_KDC_PORT}"

    @staticmethod
    def _shim(tmp_path) -> str:
        """An executable stand-in for Firefox, never exec'd: every case fails before launch.

        find_firefox runs ahead of all the ticket work, so a case without --firefox-path
        would exit 1 on a machine with no Firefox installed and reach its own failure only
        on one that has it. The shim is what makes these exit codes the argv's property.
        """
        shim = tmp_path / "firefox"
        shim.touch()
        shim.chmod(shim.stat().st_mode | stat.S_IEXEC)
        return str(shim)

    @staticmethod
    def _assert_the_paired_contract(
        argv: list[str], *, expected_code: int, expected_message: str
    ) -> None:
        """Run one path twice, plain and with --verbose, and assert both halves of F2.3.

        One helper rather than three copies of the same assertions: the three classes that
        produce an Error: line differ in their argv and their sentence and in nothing else.
        The exit-2 case does not come through here, because argparse's surface is
        deliberately not this shape.
        """
        plain = run_main_subprocess(argv)
        verbose = run_main_subprocess([*argv, "--verbose"])

        assert plain.returncode == expected_code
        assert f"Error: {expected_message}" in plain.stderr
        assert "Traceback (most recent call last)" not in plain.stderr
        assert "Traceback (most recent call last)" not in plain.stdout

        assert f"Error: {expected_message}" in verbose.stderr
        assert "Traceback (most recent call last)" in verbose.stderr
        # The message first, the trace after it, so what the user has to act on is not
        # buried under the frames they asked for.
        assert verbose.stderr.index("Error: ") < verbose.stderr.index(
            "Traceback (most recent call last)"
        )
        # A traceback is diagnostic output, so it goes where the error line went.
        assert "Traceback (most recent call last)" not in verbose.stdout
        # --verbose adds output; it does not change the outcome.
        assert verbose.returncode == plain.returncode

    def test_a_missing_ccache_exits_three_with_the_message_and_the_traceback_on_demand(
        self, tmp_path
    ):
        absent = tmp_path / "absent.ccache"

        self._assert_the_paired_contract(
            [
                "--domain", "d.local",
                "--ccache", str(absent),
                "--firefox-path", self._shim(tmp_path),
            ],
            expected_code=errors.EXIT_TICKET,
            expected_message=errors.ticket_file_message(
                str(absent), reason=errors.TICKET_REASON_MISSING, flag="--ccache"
            ),
        )

    def test_a_refused_kdc_exits_four_with_the_message_and_the_traceback_on_demand(
        self, tmp_path
    ):
        # The one case here that opens a socket, and only to loopback. --domain matches the
        # realm the fixture is forged in, so the run fails on the connection rather than on
        # a realm the request was built for.
        tgt = str(tmp_path / "tgt.ccache")
        make_dummy_ccache(tgt, self.TGT_SPN)

        self._assert_the_paired_contract(
            [
                "--domain", "test.local",
                "--dc-ip", self.DC_IP,
                "--tgt", tgt,
                "--firefox-path", self._shim(tmp_path),
            ],
            expected_code=errors.EXIT_KDC_UNREACHABLE,
            expected_message=errors.kdc_unreachable_message(
                self.KDC_ADDRESS, reason=errors.KDC_REASON_REFUSED
            ),
        )

    def test_a_non_executable_firefox_exits_one_with_the_message_and_the_traceback_on_demand(
        self, tmp_path
    ):
        # touch() leaves the execute bit off on macOS and Linux alike, which is what
        # find_firefox's os.access(path, os.X_OK) gate rejects. That gate runs before the
        # ccache is validated, so the parsable ccache here only keeps the argv well formed.
        not_executable = tmp_path / "firefox-not-executable"
        not_executable.touch()
        ccache = str(tmp_path / "good.ccache")
        make_dummy_ccache(ccache, self.AZURE_SPN)

        self._assert_the_paired_contract(
            [
                "--domain", "test.local",
                "--ccache", ccache,
                "--firefox-path", str(not_executable),
            ],
            expected_code=errors.EXIT_ENVIRONMENT,
            expected_message=errors.firefox_launch_message(
                str(not_executable), reason=errors.FIREFOX_REASON_NOT_EXECUTABLE
            ),
        )

    # The value --adssoacc-ntlm carries below. Nothing could mistake it for a key, so its
    # absence from a stream is meaningful, and it is not hex at any length.
    NOT_HEX = "not-hex-at-all"

    USAGE_ARGV = [
        "--domain", "d.local", "--user", "admin",
        "--user-sid", "S-1-5-21-1111111111-2222222222-3333333333-1234",
        "--adssoacc-ntlm", NOT_HEX,
    ]

    @pytest.mark.parametrize("extra_argv", [[], ["--verbose"]])
    def test_argparses_exit_two_carries_no_error_line_and_no_traceback_either_way(
        self, extra_argv
    ):
        """The class whose asymmetry is the frozen surface rather than a gap.

        parser.error is argparse's own exit-2 path, so the handler adds no Error: line to
        it; and parse_args runs before main()'s try, so --verbose has no recorded failure
        to print a traceback from either. Both directions therefore look identical, which
        is why this case cannot come through _assert_the_paired_contract.

        The credential half rides on the same two runs rather than on two more: stage
        acceptance criterion 9 is that the value of a credential flag reaches neither
        stream, and --verbose is the direction that had no real-process test.
        """
        result = run_main_subprocess([*self.USAGE_ARGV, *extra_argv])

        assert result.returncode == errors.EXIT_USAGE
        # The lengths come off cli's own table, so the sentence stays derived end to end.
        assert errors.hex_format_message(
            "--adssoacc-ntlm",
            expected_lengths=cli._HEX_FLAG_LENGTHS["--adssoacc-ntlm"],
            got_length=len(self.NOT_HEX),
        ) in result.stderr
        assert "Error: " not in result.stderr
        assert "Traceback (most recent call last)" not in result.stderr
        # The message reports the length received; the value itself goes nowhere, and the
        # scrollback of a red-team tool outlives the process.
        assert self.NOT_HEX not in result.stdout
        assert self.NOT_HEX not in result.stderr


class TestOktaDerivationFailureAcrossAProcess:
    """S2-R24/F2.1: an Azure ticket under --idp okta with no --okta-org exits 3 in a real
    process, and no guessed Okta host reaches either stream.

    The real-process half of TestOktaHostDerivation, which drives the same rule in process
    around tests/test_cli.py:1319. Neither half substitutes for the other: the in-process
    one patches mkdtemp so it can read the user.js and krb5.conf main() wrote, and only a
    real process can show that no traceback printed, because a SystemExit never reaches the
    interpreter's traceback printer in process.

    This is where the repro sweep's F1 and F2 cases land. Both pass --idp okta with
    --ccache/--tgs and no --okta-org against a ccache carrying an Azure SPN, so S2-R10's
    third bullet applies: with no Okta Agentless DSSO SPN to read a host from, the run
    raises TicketError rather than guessing one, and exit 3 is the specified outcome. The
    sweep's S2-R24 row expected exit 0 from a derivation that fixture cannot supply; the
    property that row was guarding is the one LEAK pins here, on both streams and in both
    verbosity directions.
    """

    # What make_dummy_ccache is handed. It forges into TEST.LOCAL and appends that realm,
    # so the ticket carries FOUND_SPN -- a realm-qualified Azure SPN, which is the shape
    # that makes the org derivable here rather than a near miss.
    AZURE_SPN = "HTTP/autologon.microsoftazuread-sso.com"
    FOUND_SPN = f"{AZURE_SPN}@TEST.LOCAL"

    # The host that would be written if an underived org were interpolated into the Okta
    # SPN template: the leak this run closed, on the one path that used to produce it.
    LEAK = "None.kerberos."

    TRACEBACK = "Traceback (most recent call last)"

    @pytest.mark.parametrize("ticket_flag", ["--ccache", "--tgs"])
    def test_an_azure_ticket_under_idp_okta_exits_three_and_guesses_no_host(
        self, ticket_flag, tmp_path
    ):
        ccache = str(tmp_path / "azure.ccache")
        make_dummy_ccache(ccache, self.AZURE_SPN)
        # errors.py owns the sentence; typing it here would pin the test's wording rather
        # than the builder's, and the two could then drift apart unnoticed.
        expected = errors.okta_org_not_derivable_message(
            ccache, found_spns=(self.FOUND_SPN,)
        )
        # find_firefox runs ahead of all the ticket work, so --firefox-path has to satisfy
        # its os.access(path, os.X_OK) gate or the run exits 1 on a machine with no Firefox
        # and never reaches the derivation. It is never exec'd: the run fails while reading
        # the ticket, well before launch. sys.executable is the one path guaranteed to exist
        # and be executable wherever this suite runs.
        argv = [
            "--domain", "d.local",
            "--idp", "okta",
            ticket_flag, ccache,
            "--firefox-path", sys.executable,
        ]

        plain = run_main_subprocess(argv)
        verbose = run_main_subprocess([*argv, "--verbose"])

        assert plain.returncode == errors.EXIT_TICKET
        assert f"Error: {expected}" in plain.stderr
        assert self.TRACEBACK not in plain.stderr
        assert self.TRACEBACK not in plain.stdout

        # The positive control that keeps the absence above honest: the same argv through
        # the same harness does print a traceback when it is asked for, so the plain run's
        # clean stderr is a property of main() and not of a harness that cannot see one.
        assert verbose.returncode == errors.EXIT_TICKET
        assert f"Error: {expected}" in verbose.stderr
        assert self.TRACEBACK in verbose.stderr
        assert verbose.stderr.index("Error: ") < verbose.stderr.index(self.TRACEBACK)
        assert self.TRACEBACK not in verbose.stdout

        # Both directions: --verbose adds frames, and a frame naming a guessed host would
        # leak it just as surely as a generated profile would.
        for result in (plain, verbose):
            assert self.LEAK not in result.stdout
            assert self.LEAK not in result.stderr
