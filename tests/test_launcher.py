import stat
from unittest.mock import MagicMock, patch

from seamless_sso_browser.launcher import cleanup, find_firefox, launch_firefox


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


class TestLaunchFirefoxEnv:
    def _run(self, tmp_path, monkeypatch, verbose):
        monkeypatch.delenv("KRB5_TRACE", raising=False)
        monkeypatch.delenv("NSPR_LOG_MODULES", raising=False)
        krb5 = tmp_path / "krb5.conf"
        krb5.write_text("[libdefaults]\n")

        captured = {}

        def fake_popen(cmd, env=None, stderr=None):
            captured["env"] = env
            proc = MagicMock()
            proc.wait.return_value = 0
            return proc

        with patch(
            "seamless_sso_browser.launcher.subprocess.Popen", side_effect=fake_popen
        ), patch("seamless_sso_browser.launcher.signal.signal"):
            launch_firefox(
                firefox_path="/usr/bin/firefox",
                profile_dir=str(tmp_path / "profile"),
                ccache_path=str(tmp_path / "x.ccache"),
                krb5_conf_path=str(krb5),
                target_url="https://example.com",
                verbose=verbose,
            )
        return captured["env"]

    def test_sets_kerberos_env_always(self, tmp_path, monkeypatch):
        env = self._run(tmp_path, monkeypatch, verbose=False)
        assert env["KRB5CCNAME"].endswith("x.ccache")
        assert env["KRB5_CONFIG"].endswith("krb5.conf")

    def test_verbose_enables_tracing(self, tmp_path, monkeypatch):
        env = self._run(tmp_path, monkeypatch, verbose=True)
        assert env["KRB5_TRACE"] == "/dev/stderr"
        assert env["NSPR_LOG_MODULES"] == "negotiateauth:5"

    def test_non_verbose_omits_tracing(self, tmp_path, monkeypatch):
        env = self._run(tmp_path, monkeypatch, verbose=False)
        assert "KRB5_TRACE" not in env
        assert "NSPR_LOG_MODULES" not in env
