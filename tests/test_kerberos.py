import base64
import os
from unittest.mock import MagicMock, patch

import pytest
from impacket.krb5.ccache import CCache

from seamless_sso_browser.kerberos import (
    ccache_from_tgs,
    load_ticket,
    parse_user_sid,
    tgs_from_credentials,
    tgs_from_tgt,
)
from tests.conftest import make_dummy_ccache, make_dummy_kirbi


class TestParseUserSid:
    def test_valid_sid(self):
        domain_sid, user_rid = parse_user_sid("S-1-5-21-111-222-333-1234")
        assert domain_sid == "S-1-5-21-111-222-333"
        assert user_rid == 1234

    def test_valid_sid_large_values(self):
        domain_sid, user_rid = parse_user_sid(
            "S-1-5-21-1111111111-2222222222-3333333333-9999"
        )
        assert domain_sid == "S-1-5-21-1111111111-2222222222-3333333333"
        assert user_rid == 9999

    def test_malformed_sid_no_dashes(self):
        with pytest.raises(ValueError):
            parse_user_sid("not-a-sid")

    def test_malformed_sid_non_numeric_rid(self):
        with pytest.raises(ValueError):
            parse_user_sid("S-1-5-21-111-222-333-abc")

    def test_malformed_sid_too_short(self):
        with pytest.raises(ValueError):
            parse_user_sid("S-1-5")


class TestLoadTicket:
    def test_ccache_file(self, tmp_path):
        ccache_path = str(tmp_path / "test.ccache")
        make_dummy_ccache(ccache_path, "HTTP/test.example.com")

        result = load_ticket(ccache_path)

        assert isinstance(result, CCache)
        assert len(result.credentials) == 1

    def test_kirbi_file(self, tmp_path):
        ccache_path = str(tmp_path / "test.ccache")
        kirbi_path = str(tmp_path / "test.kirbi")
        make_dummy_ccache(ccache_path, "HTTP/test.example.com")
        make_dummy_kirbi(ccache_path, kirbi_path)

        result = load_ticket(kirbi_path)

        assert isinstance(result, CCache)
        assert len(result.credentials) == 1

    def test_base64_ccache(self, tmp_path):
        ccache_path = str(tmp_path / "test.ccache")
        make_dummy_ccache(ccache_path, "HTTP/test.example.com")
        with open(ccache_path, "rb") as f:
            b64 = base64.b64encode(f.read()).decode()

        result = load_ticket(b64)

        assert isinstance(result, CCache)
        assert len(result.credentials) == 1

    def test_base64_kirbi(self, tmp_path):
        ccache_path = str(tmp_path / "test.ccache")
        make_dummy_ccache(ccache_path, "HTTP/test.example.com")
        ccache = CCache.loadFile(ccache_path)
        kirbi_data = ccache.toKRBCRED()
        b64 = base64.b64encode(kirbi_data).decode()

        result = load_ticket(b64)

        assert isinstance(result, CCache)
        assert len(result.credentials) == 1

    def test_invalid_file(self, tmp_path):
        bad_path = str(tmp_path / "garbage.bin")
        with open(bad_path, "wb") as f:
            f.write(b"not a ticket")

        with pytest.raises(ValueError, match="not a valid ccache or kirbi"):
            load_ticket(bad_path)

    def test_invalid_base64(self):
        with pytest.raises(ValueError, match="not a file path and not valid base64"):
            load_ticket("///not-base64-and-not-a-path!!!")

    def test_nonexistent_file_treated_as_base64(self):
        with pytest.raises(ValueError):
            load_ticket("/nonexistent/path/to/file.ccache")


class TestCcacheFromTgs:
    def test_from_ccache_file(self, tmp_path):
        ccache_path = str(tmp_path / "tgs.ccache")
        make_dummy_ccache(ccache_path, "HTTP/autologon.microsoftazuread-sso.com")

        result = ccache_from_tgs(ccache_path, str(tmp_path))

        assert os.path.isfile(result)
        loaded = CCache.loadFile(result)
        assert len(loaded.credentials) == 1

    def test_from_kirbi_file(self, tmp_path):
        ccache_path = str(tmp_path / "tgs.ccache")
        kirbi_path = str(tmp_path / "tgs.kirbi")
        make_dummy_ccache(ccache_path, "HTTP/autologon.microsoftazuread-sso.com")
        make_dummy_kirbi(ccache_path, kirbi_path)

        result = ccache_from_tgs(kirbi_path, str(tmp_path))

        assert os.path.isfile(result)
        loaded = CCache.loadFile(result)
        assert len(loaded.credentials) == 1

    def test_from_base64(self, tmp_path):
        ccache_path = str(tmp_path / "tgs.ccache")
        make_dummy_ccache(ccache_path, "HTTP/autologon.microsoftazuread-sso.com")
        with open(ccache_path, "rb") as f:
            b64 = base64.b64encode(f.read()).decode()

        result = ccache_from_tgs(b64, str(tmp_path))

        assert os.path.isfile(result)

    def test_output_path_is_in_work_dir(self, tmp_path):
        ccache_path = str(tmp_path / "tgs.ccache")
        make_dummy_ccache(ccache_path, "HTTP/autologon.microsoftazuread-sso.com")

        result = ccache_from_tgs(ccache_path, str(tmp_path))

        assert result.startswith(str(tmp_path))


class TestTgsFromCredentials:
    @patch("seamless_sso_browser.kerberos._save_tgs_as_ccache")
    @patch("seamless_sso_browser.kerberos.getKerberosTGS")
    @patch("seamless_sso_browser.kerberos.getKerberosTGT")
    def test_password_auth(self, mock_get_tgt, mock_get_tgs, mock_save, tmp_path):
        mock_get_tgt.return_value = (b"tgt", MagicMock(), MagicMock(), MagicMock())
        mock_get_tgs.return_value = (b"tgs", MagicMock(), MagicMock(), MagicMock())
        mock_save.side_effect = lambda tgs, old, new, path: make_dummy_ccache(
            path, "HTTP/dummy"
        )

        result = tgs_from_credentials(
            domain="test.local",
            dc_ip="10.0.0.1",
            username="admin",
            work_dir=str(tmp_path),
            password="Password1",
        )

        assert os.path.isfile(result)
        mock_get_tgt.assert_called_once()
        assert mock_get_tgs.call_count == 2

    @patch("seamless_sso_browser.kerberos._save_tgs_as_ccache")
    @patch("seamless_sso_browser.kerberos.getKerberosTGS")
    @patch("seamless_sso_browser.kerberos.getKerberosTGT")
    def test_ntlm_hash_auth(self, mock_get_tgt, mock_get_tgs, mock_save, tmp_path):
        mock_get_tgt.return_value = (b"tgt", MagicMock(), MagicMock(), MagicMock())
        mock_get_tgs.return_value = (b"tgs", MagicMock(), MagicMock(), MagicMock())
        mock_save.side_effect = lambda tgs, old, new, path: make_dummy_ccache(
            path, "HTTP/dummy"
        )

        result = tgs_from_credentials(
            domain="test.local",
            dc_ip="10.0.0.1",
            username="admin",
            work_dir=str(tmp_path),
            nthash="aabbccdd" * 4,
        )

        assert os.path.isfile(result)
        call_args = mock_get_tgt.call_args
        # password should be empty string, nthash should be bytes
        assert call_args[0][1] == ""

    @patch("seamless_sso_browser.kerberos._save_tgs_as_ccache")
    @patch("seamless_sso_browser.kerberos.getKerberosTGS")
    @patch("seamless_sso_browser.kerberos.getKerberosTGT")
    def test_ntlm_hash_with_lm(self, mock_get_tgt, mock_get_tgs, mock_save, tmp_path):
        mock_get_tgt.return_value = (b"tgt", MagicMock(), MagicMock(), MagicMock())
        mock_get_tgs.return_value = (b"tgs", MagicMock(), MagicMock(), MagicMock())
        mock_save.side_effect = lambda tgs, old, new, path: make_dummy_ccache(
            path, "HTTP/dummy"
        )

        result = tgs_from_credentials(
            domain="test.local",
            dc_ip="10.0.0.1",
            username="admin",
            work_dir=str(tmp_path),
            nthash="aa" * 16 + ":" + "bb" * 16,
        )

        assert os.path.isfile(result)
        call_args = mock_get_tgt.call_args
        assert call_args[0][3] == bytes.fromhex("aa" * 16)  # lmhash
        assert call_args[0][4] == bytes.fromhex("bb" * 16)  # nthash

    @patch("seamless_sso_browser.kerberos._save_tgs_as_ccache")
    @patch("seamless_sso_browser.kerberos.getKerberosTGS")
    @patch("seamless_sso_browser.kerberos.getKerberosTGT")
    def test_aes_key_auth(self, mock_get_tgt, mock_get_tgs, mock_save, tmp_path):
        mock_get_tgt.return_value = (b"tgt", MagicMock(), MagicMock(), MagicMock())
        mock_get_tgs.return_value = (b"tgs", MagicMock(), MagicMock(), MagicMock())
        mock_save.side_effect = lambda tgs, old, new, path: make_dummy_ccache(
            path, "HTTP/dummy"
        )

        result = tgs_from_credentials(
            domain="test.local",
            dc_ip="10.0.0.1",
            username="admin",
            work_dir=str(tmp_path),
            aes_key="cc" * 32,
        )

        assert os.path.isfile(result)
        call_args = mock_get_tgt.call_args
        assert call_args[0][5] == "cc" * 32  # aesKey

    @patch("seamless_sso_browser.kerberos._save_tgs_as_ccache")
    @patch("seamless_sso_browser.kerberos.getKerberosTGS")
    @patch("seamless_sso_browser.kerberos.getKerberosTGT")
    def test_requests_both_spns(self, mock_get_tgt, mock_get_tgs, mock_save, tmp_path):
        mock_get_tgt.return_value = (b"tgt", MagicMock(), MagicMock(), MagicMock())
        mock_get_tgs.return_value = (b"tgs", MagicMock(), MagicMock(), MagicMock())
        mock_save.side_effect = lambda tgs, old, new, path: make_dummy_ccache(
            path, "HTTP/dummy"
        )

        tgs_from_credentials(
            domain="test.local",
            dc_ip="10.0.0.1",
            username="admin",
            work_dir=str(tmp_path),
            password="pass",
        )

        spns = [str(call[0][0]) for call in mock_get_tgs.call_args_list]
        assert any("autologon" in s for s in spns)
        assert any("aadg" in s for s in spns)

    @patch("seamless_sso_browser.kerberos._save_tgs_as_ccache")
    @patch("seamless_sso_browser.kerberos.getKerberosTGS")
    @patch("seamless_sso_browser.kerberos.getKerberosTGT")
    def test_single_spn_no_merge(self, mock_get_tgt, mock_get_tgs, mock_save, tmp_path):
        mock_get_tgt.return_value = (b"tgt", MagicMock(), MagicMock(), MagicMock())
        mock_get_tgs.return_value = (b"tgs", MagicMock(), MagicMock(), MagicMock())
        mock_save.side_effect = lambda tgs, old, new, path: make_dummy_ccache(
            path, "HTTP/dummy"
        )

        result = tgs_from_credentials(
            domain="test.local",
            dc_ip="10.0.0.1",
            username="admin",
            work_dir=str(tmp_path),
            password="pass",
            spns=["HTTP/x.kerberos.okta.com"],
        )

        assert os.path.isfile(result)
        assert mock_get_tgs.call_count == 1

    @patch("seamless_sso_browser.kerberos._save_tgs_as_ccache")
    @patch("seamless_sso_browser.kerberos.getKerberosTGS")
    @patch("seamless_sso_browser.kerberos.getKerberosTGT")
    def test_default_spns_requests_both(
        self, mock_get_tgt, mock_get_tgs, mock_save, tmp_path
    ):
        mock_get_tgt.return_value = (b"tgt", MagicMock(), MagicMock(), MagicMock())
        mock_get_tgs.return_value = (b"tgs", MagicMock(), MagicMock(), MagicMock())
        mock_save.side_effect = lambda tgs, old, new, path: make_dummy_ccache(
            path, "HTTP/dummy"
        )

        tgs_from_credentials(
            domain="test.local",
            dc_ip="10.0.0.1",
            username="admin",
            work_dir=str(tmp_path),
            password="pass",
            spns=None,
        )

        spns = [str(call[0][0]) for call in mock_get_tgs.call_args_list]
        assert mock_get_tgs.call_count == 2
        assert any("autologon" in s for s in spns)
        assert any("aadg" in s for s in spns)


class TestTgsFromTgt:
    @patch("seamless_sso_browser.kerberos._save_tgs_as_ccache")
    @patch("seamless_sso_browser.kerberos.getKerberosTGS")
    def test_from_ccache_file(self, mock_get_tgs, mock_save, tmp_path):
        tgt_path = str(tmp_path / "tgt.ccache")
        make_dummy_ccache(tgt_path, "krbtgt/TEST.LOCAL@TEST.LOCAL")
        mock_get_tgs.return_value = (b"tgs", MagicMock(), MagicMock(), MagicMock())
        mock_save.side_effect = lambda tgs, old, new, path: make_dummy_ccache(
            path, "HTTP/dummy"
        )

        result = tgs_from_tgt(tgt_path, "test.local", "10.0.0.1", str(tmp_path))

        assert os.path.isfile(result)
        assert mock_get_tgs.call_count == 2

    @patch("seamless_sso_browser.kerberos._save_tgs_as_ccache")
    @patch("seamless_sso_browser.kerberos.getKerberosTGS")
    def test_from_base64(self, mock_get_tgs, mock_save, tmp_path):
        tgt_path = str(tmp_path / "tgt.ccache")
        make_dummy_ccache(tgt_path, "krbtgt/TEST.LOCAL@TEST.LOCAL")
        with open(tgt_path, "rb") as f:
            b64 = base64.b64encode(f.read()).decode()
        mock_get_tgs.return_value = (b"tgs", MagicMock(), MagicMock(), MagicMock())
        mock_save.side_effect = lambda tgs, old, new, path: make_dummy_ccache(
            path, "HTTP/dummy"
        )

        result = tgs_from_tgt(b64, "test.local", "10.0.0.1", str(tmp_path))

        assert os.path.isfile(result)

    @patch("seamless_sso_browser.kerberos._save_tgs_as_ccache")
    @patch("seamless_sso_browser.kerberos.getKerberosTGS")
    def test_from_kirbi_file(self, mock_get_tgs, mock_save, tmp_path):
        tgt_ccache = str(tmp_path / "tgt.ccache")
        tgt_kirbi = str(tmp_path / "tgt.kirbi")
        make_dummy_ccache(tgt_ccache, "krbtgt/TEST.LOCAL@TEST.LOCAL")
        make_dummy_kirbi(tgt_ccache, tgt_kirbi)
        mock_get_tgs.return_value = (b"tgs", MagicMock(), MagicMock(), MagicMock())
        mock_save.side_effect = lambda tgs, old, new, path: make_dummy_ccache(
            path, "HTTP/dummy"
        )

        result = tgs_from_tgt(tgt_kirbi, "test.local", "10.0.0.1", str(tmp_path))

        assert os.path.isfile(result)

    @patch("seamless_sso_browser.kerberos._save_tgs_as_ccache")
    @patch("seamless_sso_browser.kerberos.getKerberosTGS")
    def test_requests_both_spns(self, mock_get_tgs, mock_save, tmp_path):
        tgt_path = str(tmp_path / "tgt.ccache")
        make_dummy_ccache(tgt_path, "krbtgt/TEST.LOCAL@TEST.LOCAL")
        mock_get_tgs.return_value = (b"tgs", MagicMock(), MagicMock(), MagicMock())
        mock_save.side_effect = lambda tgs, old, new, path: make_dummy_ccache(
            path, "HTTP/dummy"
        )

        tgs_from_tgt(tgt_path, "test.local", "10.0.0.1", str(tmp_path))

        spns = [str(call[0][0]) for call in mock_get_tgs.call_args_list]
        assert any("autologon" in s for s in spns)
        assert any("aadg" in s for s in spns)

    @patch("seamless_sso_browser.kerberos._save_tgs_as_ccache")
    @patch("seamless_sso_browser.kerberos.getKerberosTGS")
    def test_single_spn_no_merge(self, mock_get_tgs, mock_save, tmp_path):
        tgt_path = str(tmp_path / "tgt.ccache")
        make_dummy_ccache(tgt_path, "krbtgt/TEST.LOCAL@TEST.LOCAL")
        mock_get_tgs.return_value = (b"tgs", MagicMock(), MagicMock(), MagicMock())
        mock_save.side_effect = lambda tgs, old, new, path: make_dummy_ccache(
            path, "HTTP/dummy"
        )

        result = tgs_from_tgt(
            tgt_path, "test.local", "10.0.0.1", str(tmp_path),
            spns=["HTTP/x.kerberos.okta.com"],
        )

        assert os.path.isfile(result)
        assert mock_get_tgs.call_count == 1

    @patch("seamless_sso_browser.kerberos._save_tgs_as_ccache")
    @patch("seamless_sso_browser.kerberos.getKerberosTGS")
    def test_default_spns_requests_both(self, mock_get_tgs, mock_save, tmp_path):
        tgt_path = str(tmp_path / "tgt.ccache")
        make_dummy_ccache(tgt_path, "krbtgt/TEST.LOCAL@TEST.LOCAL")
        mock_get_tgs.return_value = (b"tgs", MagicMock(), MagicMock(), MagicMock())
        mock_save.side_effect = lambda tgs, old, new, path: make_dummy_ccache(
            path, "HTTP/dummy"
        )

        tgs_from_tgt(
            tgt_path, "test.local", "10.0.0.1", str(tmp_path),
            spns=None,
        )

        spns = [str(call[0][0]) for call in mock_get_tgs.call_args_list]
        assert mock_get_tgs.call_count == 2
        assert any("autologon" in s for s in spns)
        assert any("aadg" in s for s in spns)
