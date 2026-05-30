import stat

from seamless_sso_browser.launcher import cleanup, find_firefox


class TestFindFirefox:
    def test_finds_firefox_at_explicit_path(self, tmp_path):
        fake_firefox = tmp_path / "firefox"
        fake_firefox.touch()
        fake_firefox.chmod(fake_firefox.stat().st_mode | stat.S_IEXEC)
        result = find_firefox(str(fake_firefox))
        assert result == str(fake_firefox)

    def test_raises_on_missing_explicit_path(self, tmp_path):
        try:
            find_firefox(str(tmp_path / "nonexistent"))
            raise AssertionError("Should have raised SystemExit")
        except SystemExit as e:
            assert e.code == 1

    def test_raises_when_not_on_path_and_no_explicit(self, monkeypatch):
        monkeypatch.setattr("seamless_sso_browser.launcher.shutil.which", lambda _: None)
        try:
            find_firefox(None)
            raise AssertionError("Should have raised SystemExit")
        except SystemExit as e:
            assert e.code == 1


class TestCleanup:
    def test_removes_temp_dir(self, tmp_path):
        target = tmp_path / "session"
        target.mkdir()
        (target / "somefile").touch()
        cleanup(str(target))
        assert not target.exists()

    def test_removes_ccache_if_provided(self, tmp_path):
        ccache = tmp_path / "forged.ccache"
        ccache.touch()
        cleanup(str(tmp_path / "nonexistent"), ccache_path=str(ccache))
        assert not ccache.exists()

    def test_skips_missing_paths_without_error(self, tmp_path):
        cleanup(str(tmp_path / "nope"), ccache_path=str(tmp_path / "also_nope"))
