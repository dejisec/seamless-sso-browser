import os

from impacket.krb5.ccache import CCache

from seamless_sso_browser.forger import merge_ccaches
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
