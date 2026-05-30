import pytest

from seamless_sso_browser.cli import parse_args


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
