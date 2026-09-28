import os
import re
from unittest.mock import patch

from impacket.krb5.ccache import CCache

from seamless_sso_browser.forger import AADG_SPN, AUTOLOGON_SPN, forge_tickets, merge_ccaches
from tests.conftest import make_dummy_ccache


class TestMergeCcaches:
    def test_merged_ccache_has_both_credentials(self, tmp_path):
        path_a = str(tmp_path / "a.ccache")
        path_b = str(tmp_path / "b.ccache")
        output = str(tmp_path / "merged.ccache")

        make_dummy_ccache(path_a, "HTTP/autologon.microsoftazuread-sso.com")
        make_dummy_ccache(path_b, "HTTP/aadg.windows.net.nsatc.net")

        merge_ccaches(path_a, path_b, output)

        merged = CCache.loadFile(output)
        assert len(merged.credentials) == 2

    def test_merged_ccache_file_exists(self, tmp_path):
        path_a = str(tmp_path / "a.ccache")
        path_b = str(tmp_path / "b.ccache")
        output = str(tmp_path / "merged.ccache")

        make_dummy_ccache(path_a, "HTTP/autologon.microsoftazuread-sso.com")
        make_dummy_ccache(path_b, "HTTP/aadg.windows.net.nsatc.net")

        result = merge_ccaches(path_a, path_b, output)

        assert result == output
        assert os.path.isfile(output)


class TestForgeTickets:
    """Tests for forge_tickets() SPN parameterization (C: S1-R5)."""

    DOMAIN = "test.local"
    DOMAIN_SID = "S-1-5-21-1111111111-2222222222-3333333333"
    USER = "testuser"
    USER_RID = 1000
    NTLM = "a" * 32

    def _mock_forge(self, work_dir):
        """Return a side_effect that creates a real dummy ccache."""

        def _side_effect(*, user, domain, spn, domain_sid, user_rid,
                         adssoacc_ntlm, adssoacc_aes, work_dir):
            path = os.path.join(work_dir, f"{user}.ccache")
            make_dummy_ccache(path, spn)
            return path

        return _side_effect

    @patch("seamless_sso_browser.forger._forge_single_ticket")
    def test_single_spn_no_merge(self, mock_forge, tmp_path):
        work_dir = str(tmp_path)
        mock_forge.side_effect = self._mock_forge(work_dir)

        result = forge_tickets(
            domain=self.DOMAIN,
            domain_sid=self.DOMAIN_SID,
            user=self.USER,
            user_rid=self.USER_RID,
            work_dir=work_dir,
            adssoacc_ntlm=self.NTLM,
            spns=["HTTP/x.kerberos.okta.com"],
        )

        mock_forge.assert_called_once()
        call_kwargs = mock_forge.call_args[1]
        assert call_kwargs["spn"] == "HTTP/x.kerberos.okta.com"

        # Should return the direct ccache, not combined.ccache
        assert not result.endswith("combined.ccache")
        assert result.endswith(".ccache")

        # No per-SPN temp files at all (the multi-SPN path names them .spn0, .spn1, ...)
        for f in os.listdir(work_dir):
            assert not re.search(r"\.spn\d+$", f)

    @patch("seamless_sso_browser.forger._forge_single_ticket")
    def test_default_spns_is_azure_pair(self, mock_forge, tmp_path):
        work_dir = str(tmp_path)
        mock_forge.side_effect = self._mock_forge(work_dir)

        result = forge_tickets(
            domain=self.DOMAIN,
            domain_sid=self.DOMAIN_SID,
            user=self.USER,
            user_rid=self.USER_RID,
            work_dir=work_dir,
            adssoacc_ntlm=self.NTLM,
            spns=None,
        )

        assert mock_forge.call_count == 2
        spns_called = [c[1]["spn"] for c in mock_forge.call_args_list]
        assert AUTOLOGON_SPN in spns_called
        assert AADG_SPN in spns_called
        assert result.endswith("combined.ccache")

    @patch("seamless_sso_browser.forger._forge_single_ticket")
    def test_multi_spn_merges(self, mock_forge, tmp_path):
        work_dir = str(tmp_path)
        mock_forge.side_effect = self._mock_forge(work_dir)

        result = forge_tickets(
            domain=self.DOMAIN,
            domain_sid=self.DOMAIN_SID,
            user=self.USER,
            user_rid=self.USER_RID,
            work_dir=work_dir,
            adssoacc_ntlm=self.NTLM,
            spns=["HTTP/a.com", "HTTP/b.com"],
        )

        assert mock_forge.call_count == 2
        assert result.endswith("combined.ccache")


class TestForgeWithAesKey:
    """End-to-end forging through real impacket with an AES key (no mocks).

    This exercises _build_ticketer_options + impacket's ticketer.py, the path
    every other test mocks away. It is the Okta forgery path (AES key, no NTLM
    hash) and also the Azure --adssoacc-aes path. Regression guard for the
    "Missing NT hash for Server checksum" crash.
    """

    DOMAIN = "test.local"
    DOMAIN_SID = "S-1-5-21-1111111111-2222222222-3333333333"
    USER = "testuser"
    USER_RID = 1000
    AES256 = "00" * 32  # 64 hex chars -> AES256

    def test_okta_single_spn_forge_produces_loadable_ccache(self, tmp_path):
        result = forge_tickets(
            domain=self.DOMAIN,
            domain_sid=self.DOMAIN_SID,
            user=self.USER,
            user_rid=self.USER_RID,
            work_dir=str(tmp_path),
            adssoacc_aes=self.AES256,
            spns=["HTTP/acme.kerberos.okta.com"],
        )

        assert os.path.isfile(result)
        # Loads without raising and carries the forged service ticket.
        loaded = CCache.loadFile(result)
        assert len(loaded.credentials) == 1

    def test_azure_aes_pair_forge_produces_loadable_ccache(self, tmp_path):
        result = forge_tickets(
            domain=self.DOMAIN,
            domain_sid=self.DOMAIN_SID,
            user=self.USER,
            user_rid=self.USER_RID,
            work_dir=str(tmp_path),
            adssoacc_aes=self.AES256,
            spns=None,  # defaults to the two Azure SSO SPNs, then merges
        )

        assert result.endswith("combined.ccache")
        loaded = CCache.loadFile(result)
        assert len(loaded.credentials) == 2
