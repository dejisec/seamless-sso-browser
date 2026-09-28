"""Integration tests across the module seams Okta IDP support crosses.

Covers the CLI-to-module boundaries with real objects on both sides:

  _derive_okta_spn output flows into forge_tickets.spns; forge_tickets takes
    the single-ticket path (no merge) for one Okta SPN.

  _derive_okta_spn output flows into tgs_from_tgt.spns and
    tgs_from_credentials.spns; each issues one TGS request for a single Okta
    SPN, two for the Azure default.

  trusted_uris derived from Okta args is written verbatim into Firefox
    user.js via create_firefox_profile; None falls back to SSO_SPNS.

  main() branches on --idp, derives spn_list and trusted_uris from parsed
    CLI args, and passes them correctly to every module function it calls.

  The okta-dashboard target preset resolves through parse_args and the
    resolved URL reaches launch_firefox.

  Okta and Azure flags meet _validate_mode through parse_args, which accepts
    the valid combinations and rejects the invalid ones.

Mocked only at the network/crypto boundary:
  _forge_single_ticket (impacket ticketer), getKerberosTGT, getKerberosTGS.
Process-level calls also mocked: find_firefox, launch_firefox.
tempfile.mkdtemp is patched in main() wiring tests to control the working
directory so user.js can be inspected after the run.
"""
import os
from unittest.mock import MagicMock, patch

import pytest

from seamless_sso_browser.cli import _derive_okta_spn, main, parse_args
from seamless_sso_browser.forger import forge_tickets
from seamless_sso_browser.kerberos import tgs_from_credentials, tgs_from_tgt
from seamless_sso_browser.profile import SSO_SPNS, create_firefox_profile
from tests.conftest import make_dummy_ccache

# ---------------------------------------------------------------------------
# Shared side-effects (impacket / file-creation boundary)
# ---------------------------------------------------------------------------

def _forge_single_side_effect(*, user, domain, spn, domain_sid, user_rid,
                               adssoacc_ntlm, adssoacc_aes, work_dir):
    """Write a real dummy ccache so forge_tickets can rename and merge normally."""
    path = os.path.join(work_dir, f"{user}.ccache")
    make_dummy_ccache(path, spn)
    return path


def _save_tgs_side_effect(tgs, old_key, session_key, path):
    """Write a real dummy ccache so _request_tgs_for_spns merge logic works."""
    make_dummy_ccache(path, "HTTP/dummy")


# ---------------------------------------------------------------------------
# Seam: _derive_okta_spn → forge_tickets
# ---------------------------------------------------------------------------

class TestSeamDeriveOktaSpnIntoForgeTickets:
    """SPN from _derive_okta_spn flows into forge_tickets and uses the single-ticket path."""

    _COMMON = dict(
        domain="test.local",
        domain_sid="S-1-5-21-1-2-3",
        user="testuser",
        user_rid=1000,
        adssoacc_aes="a" * 64,
    )

    @patch("seamless_sso_browser.forger._forge_single_ticket")
    def test_derived_spn_passed_to_forger(self, mock_forge, tmp_path):
        """The exact string _derive_okta_spn returns is what forge_tickets passes down."""
        mock_forge.side_effect = _forge_single_side_effect

        okta_spn = _derive_okta_spn("acme", "okta")
        forge_tickets(**self._COMMON, work_dir=str(tmp_path), spns=[okta_spn])

        mock_forge.assert_called_once()
        assert mock_forge.call_args[1]["spn"] == okta_spn

    @patch("seamless_sso_browser.forger._forge_single_ticket")
    def test_single_okta_spn_returns_direct_path_not_combined(self, mock_forge, tmp_path):
        """forge_tickets with one Okta SPN returns the ccache directly — no combined.ccache."""
        mock_forge.side_effect = _forge_single_side_effect

        okta_spn = _derive_okta_spn("acme", "okta")
        result = forge_tickets(**self._COMMON, work_dir=str(tmp_path), spns=[okta_spn])

        mock_forge.assert_called_once()
        assert not result.endswith("combined.ccache")
        assert os.path.isfile(result)

    @patch("seamless_sso_browser.forger._forge_single_ticket")
    def test_okta_spn_excludes_azure_defaults(self, mock_forge, tmp_path):
        """Forging with the Okta SPN does not use autologon or aadg SPNs."""
        mock_forge.side_effect = _forge_single_side_effect

        okta_spn = _derive_okta_spn("myorg", "oktapreview")
        forge_tickets(**self._COMMON, work_dir=str(tmp_path), spns=[okta_spn])

        called_spns = [c[1]["spn"] for c in mock_forge.call_args_list]
        assert called_spns == [okta_spn]
        assert "HTTP/autologon.microsoftazuread-sso.com" not in called_spns
        assert "HTTP/aadg.windows.net.nsatc.net" not in called_spns


# ---------------------------------------------------------------------------
# Seam: _derive_okta_spn → tgs_from_tgt
# ---------------------------------------------------------------------------

class TestSeamDeriveOktaSpnIntoTgsFromTgt:
    """SPN from _derive_okta_spn propagates through tgs_from_tgt to getKerberosTGS."""

    @patch("seamless_sso_browser.kerberos._save_tgs_as_ccache")
    @patch("seamless_sso_browser.kerberos.getKerberosTGS")
    def test_single_okta_spn_issues_one_tgs_request(self, mock_get_tgs, mock_save, tmp_path):
        """tgs_from_tgt with the derived Okta SPN calls getKerberosTGS exactly once."""
        tgt_path = str(tmp_path / "tgt.ccache")
        make_dummy_ccache(tgt_path, "krbtgt/TEST.LOCAL@TEST.LOCAL")
        mock_get_tgs.return_value = (b"tgs", MagicMock(), MagicMock(), MagicMock())
        mock_save.side_effect = _save_tgs_side_effect

        okta_spn = _derive_okta_spn("acme", "okta")
        result = tgs_from_tgt(
            tgt_path, "test.local", "10.0.0.1", str(tmp_path), spns=[okta_spn]
        )

        assert mock_get_tgs.call_count == 1
        requested_spn = str(mock_get_tgs.call_args[0][0])
        assert "acme.kerberos.okta.com" in requested_spn
        assert os.path.isfile(result)

    @patch("seamless_sso_browser.kerberos._save_tgs_as_ccache")
    @patch("seamless_sso_browser.kerberos.getKerberosTGS")
    def test_azure_none_issues_two_tgs_requests(self, mock_get_tgs, mock_save, tmp_path):
        """tgs_from_tgt with spns=None requests TGS for both Azure SSO SPNs."""
        tgt_path = str(tmp_path / "tgt.ccache")
        make_dummy_ccache(tgt_path, "krbtgt/TEST.LOCAL@TEST.LOCAL")
        mock_get_tgs.return_value = (b"tgs", MagicMock(), MagicMock(), MagicMock())
        mock_save.side_effect = _save_tgs_side_effect

        tgs_from_tgt(tgt_path, "test.local", "10.0.0.1", str(tmp_path), spns=None)

        assert mock_get_tgs.call_count == 2
        spns_requested = [str(c[0][0]) for c in mock_get_tgs.call_args_list]
        assert any("autologon" in s for s in spns_requested)
        assert any("aadg" in s for s in spns_requested)


# ---------------------------------------------------------------------------
# Seam: _derive_okta_spn → tgs_from_credentials
# ---------------------------------------------------------------------------

class TestSeamDeriveOktaSpnIntoTgsFromCredentials:
    """SPN from _derive_okta_spn propagates through tgs_from_credentials to getKerberosTGS."""

    @patch("seamless_sso_browser.kerberos._save_tgs_as_ccache")
    @patch("seamless_sso_browser.kerberos.getKerberosTGS")
    @patch("seamless_sso_browser.kerberos.getKerberosTGT")
    def test_single_okta_spn_issues_one_tgs_request(
        self, mock_get_tgt, mock_get_tgs, mock_save, tmp_path
    ):
        """tgs_from_credentials with the derived Okta SPN calls getKerberosTGS exactly once."""
        mock_get_tgt.return_value = (b"tgt", MagicMock(), MagicMock(), MagicMock())
        mock_get_tgs.return_value = (b"tgs", MagicMock(), MagicMock(), MagicMock())
        mock_save.side_effect = _save_tgs_side_effect

        okta_spn = _derive_okta_spn("acme", "okta")
        result = tgs_from_credentials(
            domain="test.local",
            dc_ip="10.0.0.1",
            username="admin",
            work_dir=str(tmp_path),
            password="Pass1",
            spns=[okta_spn],
        )

        assert mock_get_tgs.call_count == 1
        requested_spn = str(mock_get_tgs.call_args[0][0])
        assert "acme.kerberos.okta.com" in requested_spn
        assert os.path.isfile(result)

    @patch("seamless_sso_browser.kerberos._save_tgs_as_ccache")
    @patch("seamless_sso_browser.kerberos.getKerberosTGS")
    @patch("seamless_sso_browser.kerberos.getKerberosTGT")
    def test_azure_none_issues_two_tgs_requests(
        self, mock_get_tgt, mock_get_tgs, mock_save, tmp_path
    ):
        """tgs_from_credentials with spns=None requests TGS for both Azure SSO SPNs."""
        mock_get_tgt.return_value = (b"tgt", MagicMock(), MagicMock(), MagicMock())
        mock_get_tgs.return_value = (b"tgs", MagicMock(), MagicMock(), MagicMock())
        mock_save.side_effect = _save_tgs_side_effect

        tgs_from_credentials(
            domain="test.local",
            dc_ip="10.0.0.1",
            username="admin",
            work_dir=str(tmp_path),
            password="Pass1",
            spns=None,
        )

        assert mock_get_tgs.call_count == 2
        spns_requested = [str(c[0][0]) for c in mock_get_tgs.call_args_list]
        assert any("autologon" in s for s in spns_requested)
        assert any("aadg" in s for s in spns_requested)


# ---------------------------------------------------------------------------
# Seam: trusted_uris derivation → create_firefox_profile
# ---------------------------------------------------------------------------

class TestSeamProfileTrustedUris:
    """trusted_uris from main()'s Okta branch is written correctly by create_firefox_profile."""

    def test_okta_trusted_uri_replaces_azure_default(self, tmp_path):
        """create_firefox_profile with an Okta URI writes that URI and not SSO_SPNS."""
        trusted_uris = "https://acme.kerberos.okta.com"
        profile_dir = create_firefox_profile(str(tmp_path), trusted_uris=trusted_uris)

        with open(os.path.join(profile_dir, "user.js")) as f:
            content = f.read()

        assert "acme.kerberos.okta.com" in content
        assert "autologon.microsoftazuread-sso.com" not in content
        assert "aadg.windows.net.nsatc.net" not in content

    def test_azure_none_uses_sso_spns_constant(self, tmp_path):
        """create_firefox_profile with trusted_uris=None writes the exact SSO_SPNS string."""
        profile_dir = create_firefox_profile(str(tmp_path), trusted_uris=None)

        with open(os.path.join(profile_dir, "user.js")) as f:
            content = f.read()

        assert SSO_SPNS in content

    def test_main_trusted_uri_format_written_verbatim(self, tmp_path):
        """trusted_uris built with main()'s f-string format appears verbatim in user.js."""
        okta_org, okta_domain = "myorg", "oktapreview"
        # Exact format main() uses: f"https://{args.okta_org}.kerberos.{args.okta_domain}.com"
        trusted_uris = f"https://{okta_org}.kerberos.{okta_domain}.com"

        profile_dir = create_firefox_profile(str(tmp_path), trusted_uris=trusted_uris)

        with open(os.path.join(profile_dir, "user.js")) as f:
            content = f.read()

        assert f'"{trusted_uris}"' in content
        assert "network.negotiate-auth.trusted-uris" in content


# ---------------------------------------------------------------------------
# Seam: main() wiring — derived SPN list and trusted URIs
# ---------------------------------------------------------------------------

class TestSeamMainWiring:
    """main() correctly assembles Okta/Azure args and passes them to forge and profile."""

    _OKTA_FORGE = [
        "--domain", "test.local",
        "--idp", "okta",
        "--okta-org", "acme",
        "--okta-svc-aes", "a" * 64,
        "--user", "admin",
        "--user-sid", "S-1-5-21-1-2-3-4",
        "--no-cleanup",
    ]

    _AZURE_FORGE = [
        "--domain", "test.local",
        "--adssoacc-ntlm", "a" * 32,
        "--user", "admin",
        "--user-sid", "S-1-5-21-1-2-3-4",
        "--no-cleanup",
    ]

    @patch("seamless_sso_browser.cli.launch_firefox")
    @patch("seamless_sso_browser.cli.find_firefox", return_value="/usr/bin/firefox")
    @patch("seamless_sso_browser.forger._forge_single_ticket")
    def test_okta_forge_uses_derived_single_spn(
        self, mock_forge, mock_firefox, mock_launch, tmp_path
    ):
        """main() with --idp okta passes exactly the derived Okta SPN to _forge_single_ticket."""
        mock_forge.side_effect = _forge_single_side_effect

        with (
            patch("seamless_sso_browser.cli.tempfile.mkdtemp", return_value=str(tmp_path)),
            patch("sys.argv", ["seamless-sso-browser"] + self._OKTA_FORGE),
        ):
            main()

        mock_forge.assert_called_once()
        assert mock_forge.call_args[1]["spn"] == "HTTP/acme.kerberos.okta.com"

    @patch("seamless_sso_browser.cli.launch_firefox")
    @patch("seamless_sso_browser.cli.find_firefox", return_value="/usr/bin/firefox")
    @patch("seamless_sso_browser.forger._forge_single_ticket")
    def test_azure_forge_uses_both_azure_spns(
        self, mock_forge, mock_firefox, mock_launch, tmp_path
    ):
        """main() with --idp azure (default) passes both Azure SSO SPNs to _forge_single_ticket."""
        mock_forge.side_effect = _forge_single_side_effect

        with (
            patch("seamless_sso_browser.cli.tempfile.mkdtemp", return_value=str(tmp_path)),
            patch("sys.argv", ["seamless-sso-browser"] + self._AZURE_FORGE),
        ):
            main()

        assert mock_forge.call_count == 2
        spns_used = [c[1]["spn"] for c in mock_forge.call_args_list]
        assert "HTTP/autologon.microsoftazuread-sso.com" in spns_used
        assert "HTTP/aadg.windows.net.nsatc.net" in spns_used

    @patch("seamless_sso_browser.cli.launch_firefox")
    @patch("seamless_sso_browser.cli.find_firefox", return_value="/usr/bin/firefox")
    @patch("seamless_sso_browser.forger._forge_single_ticket")
    def test_okta_profile_has_okta_trusted_uri(
        self, mock_forge, mock_firefox, mock_launch, tmp_path
    ):
        """main() with --idp okta writes the Okta URI to Firefox user.js, not SSO_SPNS."""
        mock_forge.side_effect = _forge_single_side_effect

        with (
            patch("seamless_sso_browser.cli.tempfile.mkdtemp", return_value=str(tmp_path)),
            patch("sys.argv", ["seamless-sso-browser"] + self._OKTA_FORGE),
        ):
            main()

        user_js = os.path.join(str(tmp_path), "profile", "user.js")
        assert os.path.isfile(user_js)
        with open(user_js) as f:
            content = f.read()

        assert "acme.kerberos.okta.com" in content
        assert "autologon.microsoftazuread-sso.com" not in content

    @patch("seamless_sso_browser.cli.launch_firefox")
    @patch("seamless_sso_browser.cli.find_firefox", return_value="/usr/bin/firefox")
    @patch("seamless_sso_browser.forger._forge_single_ticket")
    def test_azure_profile_has_azure_sso_spns(
        self, mock_forge, mock_firefox, mock_launch, tmp_path
    ):
        """main() with --idp azure writes SSO_SPNS (Azure defaults) to Firefox user.js."""
        mock_forge.side_effect = _forge_single_side_effect

        with (
            patch("seamless_sso_browser.cli.tempfile.mkdtemp", return_value=str(tmp_path)),
            patch("sys.argv", ["seamless-sso-browser"] + self._AZURE_FORGE),
        ):
            main()

        user_js = os.path.join(str(tmp_path), "profile", "user.js")
        with open(user_js) as f:
            content = f.read()

        assert "autologon.microsoftazuread-sso.com" in content
        assert "aadg.windows.net.nsatc.net" in content


# ---------------------------------------------------------------------------
# Seam: okta-dashboard target resolution — CLI args → resolved target URL → launch
# ---------------------------------------------------------------------------

class TestSeamOktaDashboardTargetResolution:
    """The okta-dashboard preset resolves through parse_args and reaches launch."""

    _OKTA_DASHBOARD = [
        "--domain", "test.local",
        "--idp", "okta",
        "--okta-org", "acme",
        "--okta-svc-aes", "a" * 64,
        "--user", "admin",
        "--user-sid", "S-1-5-21-1-2-3-4",
        "--target", "okta-dashboard",
        "--no-cleanup",
    ]

    def test_okta_dashboard_resolves_via_parse_args(self):
        """parse_args wires --okta-org into _resolve_target for the okta-dashboard preset."""
        args = parse_args([
            "--domain", "test.local", "--idp", "okta", "--okta-org", "acme",
            "--ccache", "x", "--target", "okta-dashboard",
        ])
        assert args.target_url == "https://acme.okta.com"

    def test_okta_dashboard_without_org_errors(self):
        """okta-dashboard with no --okta-org fails at the parse_args boundary."""
        with pytest.raises(SystemExit):
            parse_args([
                "--domain", "test.local", "--ccache", "x",
                "--target", "okta-dashboard",
            ])

    @patch("seamless_sso_browser.cli.launch_firefox")
    @patch("seamless_sso_browser.cli.find_firefox", return_value="/usr/bin/firefox")
    @patch("seamless_sso_browser.forger._forge_single_ticket")
    def test_okta_dashboard_url_reaches_launch_firefox(
        self, mock_forge, mock_firefox, mock_launch, tmp_path
    ):
        """The resolved okta-dashboard URL reaches launch_firefox as target_url."""
        mock_forge.side_effect = _forge_single_side_effect

        with (
            patch("seamless_sso_browser.cli.tempfile.mkdtemp", return_value=str(tmp_path)),
            patch("sys.argv", ["seamless-sso-browser"] + self._OKTA_DASHBOARD),
        ):
            main()

        mock_launch.assert_called_once()
        assert mock_launch.call_args[1]["target_url"] == "https://acme.okta.com"


# ---------------------------------------------------------------------------
# Seam: IDP cross-checks — CLI args → _validate_mode via parse_args
# ---------------------------------------------------------------------------

class TestSeamValidateModeIdpCrossChecks:
    """Okta/Azure flags defined on the CLI meet _validate_mode through parse_args."""

    def test_okta_svc_aes_requires_idp_okta(self):
        """--okta-svc-aes without --idp okta is rejected."""
        with pytest.raises(SystemExit):
            parse_args([
                "--domain", "d", "--okta-svc-aes", "a" * 64,
                "--user", "u", "--user-sid", "S-1-5-21-1-2-3-4",
            ])

    def test_azure_forgery_rejected_with_idp_okta(self):
        """Azure --adssoacc-aes is rejected under --idp okta."""
        with pytest.raises(SystemExit):
            parse_args([
                "--domain", "d", "--idp", "okta", "--okta-org", "acme",
                "--adssoacc-aes", "a" * 64,
                "--user", "u", "--user-sid", "S-1-5-21-1-2-3-4",
            ])

    def test_nondefault_okta_domain_requires_idp_okta(self):
        """A non-default --okta-domain without --idp okta is rejected."""
        with pytest.raises(SystemExit):
            parse_args([
                "--domain", "d", "--okta-domain", "oktapreview", "--ccache", "x",
            ])

    def test_okta_svc_aes_counts_as_forgery_mode(self):
        """--okta-svc-aes participates in the auth-mode mutual exclusion."""
        with pytest.raises(SystemExit):
            parse_args([
                "--domain", "d", "--idp", "okta", "--okta-org", "acme",
                "--okta-svc-aes", "a" * 64, "--password", "pass",
                "--user", "u", "--dc-ip", "1.2.3.4",
            ])

    def test_valid_okta_forgery_yields_derived_spn(self):
        """A valid Okta forgery invocation parses and its args derive the Okta SPN."""
        args = parse_args([
            "--domain", "d", "--idp", "okta", "--okta-org", "acme",
            "--okta-svc-aes", "a" * 64, "--user", "u",
            "--user-sid", "S-1-5-21-1-2-3-4",
        ])
        spn = _derive_okta_spn(args.okta_org, args.okta_domain)
        assert spn == "HTTP/acme.kerberos.okta.com"
