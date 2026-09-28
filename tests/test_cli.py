from unittest.mock import patch

import pytest

from seamless_sso_browser.cli import _derive_okta_spn, main, parse_args


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
        args = parse_args(
            self.FORGE_ARGS + ["--target", "okta-dashboard", "--okta-org", "acme"]
        )
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


class TestOpsecMessages:
    """Test that main() output messages use IDP-appropriate terminology."""

    def _run_main_with_argv(self, argv, capsys, parse_user_sid_ret=None):
        """Run main() with patched externals, return captured stdout."""
        with (
            patch("seamless_sso_browser.cli.find_firefox", return_value="/usr/bin/firefox"),
            patch("seamless_sso_browser.cli.forge_tickets", return_value="/tmp/combined.ccache"),
            patch("seamless_sso_browser.cli.create_firefox_profile", return_value="/tmp/profile"),
            patch("seamless_sso_browser.cli.create_krb5_conf", return_value="/tmp/krb5.conf"),
            patch("seamless_sso_browser.cli.launch_firefox"),
            patch("seamless_sso_browser.cli.cleanup"),
            patch(
                "seamless_sso_browser.cli.tgs_from_credentials",
                return_value="/tmp/creds.ccache",
            ),
            patch("seamless_sso_browser.cli.tgs_from_tgt", return_value="/tmp/tgt.ccache"),
            patch("sys.argv", ["seamless-sso-browser"] + argv),
        ):
            if parse_user_sid_ret:
                with patch(
                    "seamless_sso_browser.cli.parse_user_sid",
                    return_value=parse_user_sid_ret,
                ):
                    main()
            else:
                main()
        return capsys.readouterr().out

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
