import base64
import errno
import os
import socket
from unittest.mock import MagicMock, patch

import pytest
from impacket.krb5 import constants
from impacket.krb5.ccache import CCache
from impacket.krb5.kerberosv5 import KerberosError

from seamless_sso_browser import errors
from seamless_sso_browser.errors import TicketError
from seamless_sso_browser.forger import merge_ccaches
from seamless_sso_browser.kerberos import (
    ccache_from_tgs,
    load_ticket,
    parse_user_sid,
    tgs_from_credentials,
    tgs_from_tgt,
    ticket_service_principals,
)
from tests.conftest import make_dummy_ccache, make_dummy_kirbi, make_empty_ccache


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


class TestLoadTicketFilesystemFailures:
    """S2-R5 (C1.4, C1.5): a directory, a missing file and an unreadable file are each
    reported as what they are, at exit 3, instead of as a base64 problem or a raw
    PermissionError."""

    def test_a_directory_is_reported_as_a_directory(self, tmp_path):
        with pytest.raises(TicketError) as excinfo:
            load_ticket(str(tmp_path))
        assert str(excinfo.value) == errors.ticket_file_message(
            str(tmp_path), reason=errors.TICKET_REASON_DIRECTORY
        )

    def test_the_directory_message_is_not_swallowed_by_the_format_probes(self, tmp_path):
        # Hazard: TicketError is a ValueError and load_ticket's two `except Exception`
        # probes swallow one raised inside them. If the check moves below them, this
        # message becomes "not a valid ccache or kirbi" and the user is told the wrong
        # actionable fact.
        with pytest.raises(TicketError) as excinfo:
            load_ticket(str(tmp_path))
        assert "not a valid ccache or kirbi" not in str(excinfo.value)
        assert "not valid base64" not in str(excinfo.value)

    def test_a_missing_file_in_an_existing_directory_is_reported_as_missing(self, tmp_path):
        # C1: the reproduction. /tmp/... is legal base64, so today this says base64.
        missing = str(tmp_path / "does-not-exist.ccache")
        with pytest.raises(TicketError) as excinfo:
            load_ticket(missing)
        assert str(excinfo.value) == errors.ticket_file_message(
            missing, reason=errors.TICKET_REASON_MISSING
        )

    def test_an_unreadable_file_is_reported_as_permission_denied(self, tmp_path):
        # C5/C3.1: today a raw PermissionError escapes to main()'s catch-all at exit 1.
        unreadable = tmp_path / "unreadable.ccache"
        unreadable.write_bytes(b"whatever")
        unreadable.chmod(0o000)
        try:
            with pytest.raises(TicketError) as excinfo:
                load_ticket(str(unreadable))
        finally:
            # Restore the mode so tmp_path teardown can remove it.
            unreadable.chmod(0o600)
        assert str(excinfo.value) == errors.ticket_file_message(
            str(unreadable), reason=errors.TICKET_REASON_UNREADABLE
        )

    def test_the_cause_is_chained_so_verbose_still_shows_it(self, tmp_path):
        unreadable = tmp_path / "unreadable.ccache"
        unreadable.write_bytes(b"whatever")
        unreadable.chmod(0o000)
        try:
            with pytest.raises(TicketError) as excinfo:
                load_ticket(str(unreadable))
        finally:
            unreadable.chmod(0o600)
        assert isinstance(excinfo.value.__cause__, OSError)

    @pytest.mark.parametrize(
        "value",
        [
            "/nonexistent/path/to/file.ccache",
            "///not-base64-and-not-a-path!!!",
            "missing.ccache",
        ],
        ids=["parent-does-not-exist", "root-parent", "relative-no-parent"],
    )
    def test_a_value_with_no_usable_parent_keeps_the_base64_classification(self, value):
        # Frozen by §7 and by TestLoadTicket's two existing cases. The third id is
        # deliberate, not an oversight: a bare relative path has "" for a parent, so an
        # operator who mistypes a relative --tgs path is told about base64. Keeping the
        # two pinned classifications is worth that, and this case exists so nobody
        # "fixes" it into a regression.
        with pytest.raises(ValueError) as excinfo:
            load_ticket(value)
        assert "not a file path and not valid base64" in str(excinfo.value)

    def test_every_ticket_failure_carries_exit_code_three(self, tmp_path):
        # The whole point: main() reads exc.exit_code, so these stop being exit-1
        # catch-all failures.
        garbage = tmp_path / "garbage.bin"
        garbage.write_bytes(b"not a ticket")
        values = [str(tmp_path), str(tmp_path / "gone.ccache"), str(garbage)]
        for value in values:
            with pytest.raises(TicketError) as excinfo:
                load_ticket(value)
            assert excinfo.value.exit_code == 3
            assert isinstance(excinfo.value, ValueError)


class TestTicketServicePrincipals:
    """S2-R9: the pure read that --ccache validation, the ticket-kind check and the
    SPN check all share. Returns data, prints nothing, raises nothing."""

    def test_a_service_ticket_yields_one_http_principal(self, tmp_path):
        ccache_path = str(tmp_path / "tgs.ccache")
        make_dummy_ccache(ccache_path, "HTTP/test.example.com")

        result = ticket_service_principals(load_ticket(ccache_path))

        assert len(result) == 1
        assert isinstance(result[0], str)
        assert result[0].startswith("HTTP/test.example.com")

    def test_the_realm_suffix_is_part_of_what_it_returns(self, tmp_path):
        # The caller matching against a bare SPN has to split at "@" itself; this is
        # the assertion that tells it so.
        ccache_path = str(tmp_path / "tgs.ccache")
        make_dummy_ccache(ccache_path, "HTTP/test.example.com")

        result = ticket_service_principals(load_ticket(ccache_path))

        assert "@" in result[0]
        assert result[0].split("@", 1)[0] == "HTTP/test.example.com"

    def test_a_tgt_yields_a_krbtgt_principal(self, tmp_path):
        # What the ticket-kind check reads: the first component is the service class.
        tgt_path = str(tmp_path / "tgt.ccache")
        make_dummy_ccache(tgt_path, "krbtgt/test.local")

        result = ticket_service_principals(load_ticket(tgt_path))

        assert len(result) == 1
        assert result[0].split("/", 1)[0] == "krbtgt"

    def test_a_kirbi_yields_the_same_principal_as_its_ccache(self, tmp_path):
        ccache_path = str(tmp_path / "tgs.ccache")
        kirbi_path = str(tmp_path / "tgs.kirbi")
        make_dummy_ccache(ccache_path, "HTTP/test.example.com")
        make_dummy_kirbi(ccache_path, kirbi_path)

        from_ccache = ticket_service_principals(load_ticket(ccache_path))
        from_kirbi = ticket_service_principals(load_ticket(kirbi_path))

        assert from_kirbi == from_ccache

    def test_a_ccache_with_no_credentials_yields_an_empty_list(self, tmp_path):
        # It returns [] rather than raising: the empty case is a policy decision and
        # policy lives in cli.py.
        ccache_path = str(tmp_path / "tgs.ccache")
        empty_path = str(tmp_path / "empty.ccache")
        make_dummy_ccache(ccache_path, "HTTP/test.example.com")
        make_empty_ccache(ccache_path, empty_path)

        assert ticket_service_principals(load_ticket(empty_path)) == []

    def test_it_prints_nothing(self, tmp_path, capsys):
        # NFR-7: library modules are silent. Only cli.py and launcher.py print.
        ccache_path = str(tmp_path / "tgs.ccache")
        make_dummy_ccache(ccache_path, "HTTP/test.example.com")

        ticket_service_principals(load_ticket(ccache_path))

        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err == ""

    def test_a_merged_ccache_yields_one_principal_per_credential(self, tmp_path):
        # The multi-credential case the SPN check's "at least one match" rule needs.
        first = str(tmp_path / "a.ccache")
        second = str(tmp_path / "b.ccache")
        merged = str(tmp_path / "merged.ccache")
        make_dummy_ccache(first, "HTTP/autologon.microsoftazuread-sso.com")
        make_dummy_ccache(second, "HTTP/aadg.windows.net.nsatc.net")
        merge_ccaches(first, second, merged)

        result = ticket_service_principals(load_ticket(merged))

        assert len(result) == 2
        assert {spn.split("@", 1)[0] for spn in result} == {
            "HTTP/autologon.microsoftazuread-sso.com",
            "HTTP/aadg.windows.net.nsatc.net",
        }


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
    @patch("seamless_sso_browser.kerberos._get_tgs")
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
    @patch("seamless_sso_browser.kerberos._get_tgs")
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
    @patch("seamless_sso_browser.kerberos._get_tgs")
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
    @patch("seamless_sso_browser.kerberos._get_tgs")
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
    @patch("seamless_sso_browser.kerberos._get_tgs")
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
    @patch("seamless_sso_browser.kerberos._get_tgs")
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
    @patch("seamless_sso_browser.kerberos._get_tgs")
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
    @patch("seamless_sso_browser.kerberos._get_tgs")
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
    @patch("seamless_sso_browser.kerberos._get_tgs")
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
    @patch("seamless_sso_browser.kerberos._get_tgs")
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
    @patch("seamless_sso_browser.kerberos._get_tgs")
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
    @patch("seamless_sso_browser.kerberos._get_tgs")
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
    @patch("seamless_sso_browser.kerberos._get_tgs")
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


# The DC the reproduction points at, and the port impacket names in its message.
_DC_IP = "127.0.0.1"
_KDC_PORT = 88
_TGT_RESPONSE = (b"tgt", MagicMock(), MagicMock(), MagicMock())


def _connection_error(inner: BaseException) -> OSError:
    """Build the socket.error impacket raises when it cannot reach the KDC.

    kerberosv5.py:66-67 catches socket.error and re-raises
    socket.error("Connection error (%s:%s)" % (targetHost, port), e), so the real
    failure is nested on args[1]. Constructing an OSError with two arguments makes
    .errno the first of them, which means .errno here is that message string and not
    an errno at all. socket.error is OSError; only the spelling differs, because ruff
    UP024 rejects the alias.
    """
    return OSError(f"Connection error ({_DC_IP}:{_KDC_PORT})", inner)


def _refused() -> OSError:
    """The nested failure a DC with nothing listening on 88 produces."""
    return _connection_error(ConnectionRefusedError(errno.ECONNREFUSED, "Connection refused"))


def _request_tgs(work_dir: str) -> str:
    """Drive the credential path the way cli.py's credential mode drives it."""
    return tgs_from_credentials(
        domain="test.local",
        dc_ip=_DC_IP,
        username="admin",
        work_dir=work_dir,
        password="Password1",
    )


class TestKdcFailureTranslation:
    @patch("seamless_sso_browser.kerberos.getKerberosTGT")
    def test_a_refused_connection_becomes_a_kdc_unreachable_error(self, mock_get_tgt, tmp_path):
        mock_get_tgt.side_effect = _refused()

        with pytest.raises(errors.KdcUnreachableError) as exc:
            _request_tgs(str(tmp_path))

        assert f"{_DC_IP}:{_KDC_PORT}" in str(exc.value)
        assert "connection refused" in str(exc.value)
        assert "--dc-ip" in str(exc.value)
        assert exc.value.exit_code == 4

    @patch("seamless_sso_browser.kerberos.getKerberosTGT")
    def test_an_unresolvable_dc_names_the_resolver_rather_than_a_refusal(
        self, mock_get_tgt, tmp_path
    ):
        # EAI_NONAME is 8, which is ENOEXEC as an OS errno: a reason read off the
        # outer .errno, or off the wrong argument, gets this case wrong.
        mock_get_tgt.side_effect = _connection_error(
            socket.gaierror(socket.EAI_NONAME, "nodename nor servname provided")
        )

        with pytest.raises(errors.KdcUnreachableError) as exc:
            _request_tgs(str(tmp_path))

        assert "resolve" in str(exc.value)
        assert "connection refused" not in str(exc.value)

    @patch("seamless_sso_browser.kerberos._get_tgs")
    @patch("seamless_sso_browser.kerberos.getKerberosTGT")
    def test_a_socket_failure_on_the_service_ticket_call_is_translated_too(
        self, mock_get_tgt, mock_get_tgs, tmp_path
    ):
        # The second wrap site: the TGT arrives and the service-ticket call is the one
        # that cannot reach the KDC.
        mock_get_tgt.return_value = _TGT_RESPONSE
        mock_get_tgs.side_effect = _refused()

        with pytest.raises(errors.KdcUnreachableError) as exc:
            _request_tgs(str(tmp_path))

        assert exc.value.exit_code == 4

    @patch("seamless_sso_browser.kerberos.getKerberosTGT")
    def test_a_connect_timeout_is_reported_as_a_timeout(self, mock_get_tgt, tmp_path):
        # A connect timeout arrives as a nested TimeoutError, which usually carries no
        # errno at all, so it is matched by type rather than by number.
        mock_get_tgt.side_effect = _connection_error(TimeoutError("timed out"))

        with pytest.raises(errors.KdcUnreachableError) as exc:
            _request_tgs(str(tmp_path))

        assert "timed out" in str(exc.value)
        assert "connection refused" not in str(exc.value)

    @patch("seamless_sso_browser.kerberos.getKerberosTGT")
    def test_an_errno_timeout_is_reported_as_a_timeout(self, mock_get_tgt, tmp_path):
        # The other route to the same reason: a bare OSError with .errno set to
        # ETIMEDOUT, but NOT constructed with that errno (which Python's errno ->
        # subclass mapping would turn into a TimeoutError instance, hitting the
        # isinstance(inner, TimeoutError) branch instead of this one).
        inner = OSError()
        inner.errno = errno.ETIMEDOUT
        assert not isinstance(inner, TimeoutError)
        mock_get_tgt.side_effect = _connection_error(inner)

        with pytest.raises(errors.KdcUnreachableError) as exc:
            _request_tgs(str(tmp_path))

        assert "timed out" in str(exc.value)
        assert "connection refused" not in str(exc.value)

    @patch("seamless_sso_browser.kerberos.getKerberosTGT")
    def test_an_unrecognised_errno_gets_the_generic_reason_and_no_os_text(
        self, mock_get_tgt, tmp_path
    ):
        # The default branch names a reason of its own and never the OS's own text.
        mock_get_tgt.side_effect = _connection_error(
            OSError(errno.EHOSTDOWN, "MARKER-os-text-must-not-leak")
        )

        with pytest.raises(errors.KdcUnreachableError) as exc:
            _request_tgs(str(tmp_path))

        assert errors.KDC_REASON_OTHER in str(exc.value)
        assert "MARKER-os-text-must-not-leak" not in str(exc.value)

    @patch("seamless_sso_browser.kerberos.getKerberosTGT")
    def test_the_outer_errno_is_never_what_the_reason_is_read_from(self, mock_get_tgt, tmp_path):
        # The outer .errno *is* the "Connection error (host:port)" string, so a reason
        # read from it both reports the wrong fact and leaks the string.
        mock_get_tgt.side_effect = _refused()

        with pytest.raises(errors.KdcUnreachableError) as exc:
            _request_tgs(str(tmp_path))

        assert errors.KDC_REASON_REFUSED in str(exc.value)
        assert "Connection error (" not in str(exc.value)

    @patch("seamless_sso_browser.kerberos._get_tgs")
    @patch("seamless_sso_browser.kerberos.getKerberosTGT")
    def test_a_kerberos_error_becomes_a_kdc_protocol_error_carrying_its_code_name(
        self, mock_get_tgt, mock_get_tgs, tmp_path
    ):
        mock_get_tgt.return_value = _TGT_RESPONSE
        kerberos_error = KerberosError(error=constants.ErrorCodes.KDC_ERR_WRONG_REALM.value)
        mock_get_tgs.side_effect = kerberos_error

        with pytest.raises(errors.KdcProtocolError) as exc:
            _request_tgs(str(tmp_path))

        assert exc.value.code == 68
        assert exc.value.code_name == "KDC_ERR_WRONG_REALM"
        assert exc.value.exit_code == 5
        # Chained, so --verbose still shows impacket's own traceback.
        assert exc.value.__cause__ is kerberos_error

    # The five rows the register in errors.kdc_error_message is keyed on. The name is
    # what the code is matched to; the code is the literal, because that is the number
    # impacket puts on the wire and the one this run must not get wrong.
    @pytest.mark.parametrize(
        ("name", "code"),
        [
            ("KDC_ERR_WRONG_REALM", 68),
            ("KDC_ERR_PREAUTH_FAILED", 24),
            ("KDC_ERR_S_PRINCIPAL_UNKNOWN", 7),
            ("KDC_ERR_C_PRINCIPAL_UNKNOWN", 6),
            ("KRB_AP_ERR_SKEW", 37),
        ],
    )
    @patch("seamless_sso_browser.kerberos._get_tgs")
    @patch("seamless_sso_browser.kerberos.getKerberosTGT")
    def test_every_mapped_row_resolves_to_its_own_code_and_name(
        self, mock_get_tgt, mock_get_tgs, tmp_path, name, code
    ):
        mock_get_tgt.return_value = _TGT_RESPONSE
        mock_get_tgs.side_effect = KerberosError(error=constants.ErrorCodes[name].value)

        with pytest.raises(errors.KdcProtocolError) as exc:
            _request_tgs(str(tmp_path))

        assert exc.value.code == code
        assert exc.value.code_name == name

    @patch("seamless_sso_browser.kerberos._get_tgs")
    @patch("seamless_sso_browser.kerberos.getKerberosTGT")
    def test_an_unmapped_code_still_raises_cleanly_with_no_name(
        self, mock_get_tgt, mock_get_tgs, tmp_path
    ):
        # 9999 is outside impacket's table, so getErrorString() raises KeyError and
        # ErrorCodes(9999) raises ValueError. Either one unguarded is a traceback in the
        # middle of error handling, which is the defect this run exists to remove.
        mock_get_tgt.return_value = _TGT_RESPONSE
        mock_get_tgs.side_effect = KerberosError(error=9999)

        with pytest.raises(errors.KdcProtocolError) as exc:
            _request_tgs(str(tmp_path))

        assert exc.value.code == 9999
        assert exc.value.code_name is None
        assert str(exc.value) != ""

    @patch("seamless_sso_browser.kerberos._get_tgs")
    @patch("seamless_sso_browser.kerberos.getKerberosTGT")
    def test_the_detail_is_impackets_description_and_not_its_tuple(
        self, mock_get_tgt, mock_get_tgs, tmp_path
    ):
        # getErrorString() returns ("KRB_AP_ERR_SKEW", "Clock skew too great"), so a
        # message built from it verbatim shows the operator a Python tuple.
        mock_get_tgt.return_value = _TGT_RESPONSE
        mock_get_tgs.side_effect = KerberosError(
            error=constants.ErrorCodes.KRB_AP_ERR_SKEW.value
        )

        with pytest.raises(errors.KdcProtocolError) as exc:
            _request_tgs(str(tmp_path))

        assert "Clock skew too great" in str(exc.value)
        assert "KRB_AP_ERR_SKEW'," not in str(exc.value)

    @patch("seamless_sso_browser.kerberos._get_tgs")
    @patch("seamless_sso_browser.kerberos.getKerberosTGT")
    def test_an_already_typed_failure_is_not_rewrapped(self, mock_get_tgt, mock_get_tgs, tmp_path):
        # KdcUnreachableError is an OSError, so an except OSError added here can catch
        # the very type this module raises. A typed failure keeps its own wording.
        mock_get_tgt.return_value = _TGT_RESPONSE
        mock_get_tgs.side_effect = errors.KdcUnreachableError("MARKER-already-typed")

        with pytest.raises(errors.KdcUnreachableError) as exc:
            _request_tgs(str(tmp_path))

        assert str(exc.value) == "MARKER-already-typed"

    @patch("seamless_sso_browser.kerberos.getKerberosTGT")
    def test_the_translation_prints_nothing(self, mock_get_tgt, tmp_path, capsys):
        # kerberos.py is a library module: only cli.py and launcher.py print. OSError is
        # the breadth that holds on both sides of the fix — impacket's socket.error
        # today, KdcUnreachableError once it is translated.
        mock_get_tgt.side_effect = _refused()

        with pytest.raises(OSError):
            _request_tgs(str(tmp_path))

        assert capsys.readouterr() == ("", "")

    @patch("seamless_sso_browser.kerberos.getKerberosTGT")
    def test_the_credential_path_translates_the_kdc_rejection_too(self, mock_get_tgt, tmp_path):
        # The first wrap site. PREAUTH_FAILED is the rejection a wrong credential earns,
        # so it is the row this path actually sees.
        mock_get_tgt.side_effect = KerberosError(
            error=constants.ErrorCodes.KDC_ERR_PREAUTH_FAILED.value
        )

        with pytest.raises(errors.KdcProtocolError) as exc:
            _request_tgs(str(tmp_path))

        assert exc.value.code_name == "KDC_ERR_PREAUTH_FAILED"

    @patch("seamless_sso_browser.kerberos.getKerberosTGT")
    def test_the_cause_is_chained_so_verbose_still_shows_impackets_traceback(
        self, mock_get_tgt, tmp_path
    ):
        mock_get_tgt.side_effect = KerberosError(
            error=constants.ErrorCodes.KDC_ERR_PREAUTH_FAILED.value
        )

        with pytest.raises(errors.KdcProtocolError) as exc:
            _request_tgs(str(tmp_path))

        assert isinstance(exc.value.__cause__, KerberosError)

    @patch("seamless_sso_browser.kerberos.getKerberosTGT")
    def test_the_exit_code_is_five(self, mock_get_tgt, tmp_path):
        # kerberos.py never picks a number; this asserts the class it picked carries the
        # one the exit-code table gives a KDC protocol error.
        mock_get_tgt.side_effect = KerberosError(
            error=constants.ErrorCodes.KDC_ERR_PREAUTH_FAILED.value
        )

        with pytest.raises(errors.KdcProtocolError) as exc:
            _request_tgs(str(tmp_path))

        assert exc.value.exit_code == 5

    @patch("seamless_sso_browser.kerberos.getKerberosTGT")
    def test_a_socket_failure_is_still_translated_to_exit_four(self, mock_get_tgt, tmp_path):
        # The KDC-rejection clause sits above the OSError one at both wrap sites; a
        # clause broad enough to swallow a socket failure would turn this exit 4 into 5.
        mock_get_tgt.side_effect = _refused()

        with pytest.raises(errors.KdcUnreachableError) as exc:
            _request_tgs(str(tmp_path))

        assert exc.value.exit_code == 4

    @patch("seamless_sso_browser.kerberos.getKerberosTGT")
    def test_no_credential_value_reaches_the_message(self, mock_get_tgt, tmp_path):
        # impacket's KerberosError is raised from the call the password was passed to, so
        # this is the row where a leak would happen.
        mock_get_tgt.side_effect = KerberosError(
            error=constants.ErrorCodes.KDC_ERR_PREAUTH_FAILED.value
        )

        with pytest.raises(errors.KdcProtocolError) as exc:
            tgs_from_credentials(
                domain="test.local",
                dc_ip=_DC_IP,
                username="admin",
                work_dir=str(tmp_path),
                password="MARKER-Password-2f9c",
            )

        assert "MARKER-Password-2f9c" not in str(exc.value)
