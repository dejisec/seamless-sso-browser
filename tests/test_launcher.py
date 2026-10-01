import errno
import signal
import stat
from unittest.mock import MagicMock, patch

import pytest

from seamless_sso_browser import errors
from seamless_sso_browser.errors import LocalEnvironmentError
from seamless_sso_browser.launcher import cleanup, find_firefox, launch_firefox


class TestFindFirefox:
    def test_finds_firefox_at_explicit_path(self, tmp_path):
        fake_firefox = tmp_path / "firefox"
        fake_firefox.touch()
        fake_firefox.chmod(fake_firefox.stat().st_mode | stat.S_IEXEC)
        result = find_firefox(str(fake_firefox))
        assert result == str(fake_firefox)

    def test_raises_on_missing_explicit_path(self, tmp_path):
        missing = tmp_path / "nonexistent"
        with pytest.raises(LocalEnvironmentError) as excinfo:
            find_firefox(str(missing))
        assert excinfo.value.exit_code == 1
        # The message carries no "Error: " prefix and no trailing newline: main() adds the
        # prefix, and this assertion is what keeps the stderr a user sees byte-identical.
        assert str(excinfo.value) == f"Firefox not found at {missing}"

    def test_raises_when_not_on_path_and_no_explicit(self, monkeypatch):
        monkeypatch.setattr("seamless_sso_browser.launcher.shutil.which", lambda _: None)
        with pytest.raises(LocalEnvironmentError) as excinfo:
            find_firefox(None)
        assert excinfo.value.exit_code == 1
        assert str(excinfo.value) == (
            "Firefox not found on PATH.\nInstall with: sudo apt install firefox-esr"
        )


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


class TestLaunchSignalHandlers:
    """C4.3 -- why a Ctrl+C while Firefox is running exits 0 rather than 130.

    launch_firefox installs its own SIGINT and SIGTERM handlers around proc.wait(), so
    the signal never becomes a KeyboardInterrupt in main() at all: the handler terminates
    the child, wait() returns, and launch_firefox returns normally, which is how main()
    reaches its end and exits EXIT_OK.

    The suite cannot prove the end-to-end half. signal.signal is patched out in every
    launch test in this file that reaches it -- it has to be, because the alternative is
    registering a handler inside the pytest process -- and delivering a real SIGINT to the
    test runner to find out what the exit code would be is a test that breaks the suite it
    lives in. Proving that half needs the real console script driven against a Firefox
    shim that sleeps, sent a real SIGINT, with its exit code checked from outside. What is
    provable here is the mechanism such a run depends on, and that is what this test pins.
    """

    def test_a_sigint_while_firefox_runs_terminates_the_child_without_raising(self, tmp_path):
        proc = MagicMock()
        proc.wait.return_value = 0

        # verbose=False keeps the --verbose block from opening krb5_conf_path, which does
        # not exist here.
        with patch(
            "seamless_sso_browser.launcher.subprocess.Popen", return_value=proc
        ), patch("seamless_sso_browser.launcher.signal.signal") as signal_mock:
            result = launch_firefox(
                firefox_path="/usr/bin/firefox",
                profile_dir=str(tmp_path / "profile"),
                ccache_path=str(tmp_path / "x.ccache"),
                krb5_conf_path=str(tmp_path / "krb5.conf"),
                target_url="https://example.com",
                verbose=False,
            )

        registered = {call.args[0]: call.args[1] for call in signal_mock.call_args_list}
        # SIGTERM as well as SIGINT: a kill from outside the terminal has to reach the
        # child too, or Firefox outlives the tool that launched it.
        assert signal.SIGINT in registered
        assert signal.SIGTERM in registered

        # Invoking the registered handler the way the interpreter would. This call is
        # itself the assertion that it raises nothing -- a handler that re-raised
        # KeyboardInterrupt would fail the test on this line, and that is precisely the
        # reason no KeyboardInterrupt reaches main() on this path.
        registered[signal.SIGINT](signal.SIGINT, None)

        assert proc.terminate.called
        # And launch_firefox returns normally, so main() runs on to its end rather than
        # entering an except clause with an exit code.
        assert result is None


class TestVerboseIdpRegister:
    """S2-R20/C10.2-C10.3: the tail of launch_firefox's --verbose block names the IdP
    it is launching for. "Okta precheckFailure" belongs to an Okta launch only; the
    idp parameter defaults to Azure, and an Azure launch must name none of the Azure
    register's forbidden terms."""

    @staticmethod
    def _verbose_stdout(tmp_path, capsys, **extra) -> str:
        """Run launch_firefox with --verbose and no real browser; return its stdout.

        extra is how a caller passes the idp keyword; passing nothing exercises the
        idp default, which is what a caller that omits idp gets.
        """
        krb5 = tmp_path / "krb5.conf"
        krb5.write_text("[libdefaults]\n    default_realm = D.LOCAL\n")

        proc = MagicMock()
        proc.wait.return_value = 0
        with patch(
            "seamless_sso_browser.launcher.subprocess.Popen", return_value=proc
        ), patch("seamless_sso_browser.launcher.signal.signal"):
            launch_firefox(
                firefox_path="/usr/bin/firefox",
                profile_dir=str(tmp_path / "profile"),
                ccache_path=str(tmp_path / "x.ccache"),
                krb5_conf_path=str(krb5),
                target_url="https://example.com",
                verbose=True,
                **extra,
            )
        return capsys.readouterr().out

    def test_the_verbose_block_still_prints_what_troubleshooting_needs(
        self, tmp_path, capsys
    ):
        # The control, and the reason launcher.py:49-61 is off limits: the README's
        # Troubleshooting section depends on the ccache path, the krb5.conf contents
        # and the Firefox command being printed together.
        stdout = self._verbose_stdout(tmp_path, capsys)

        assert "[*] KRB5CCNAME=" in stdout
        assert "[*] krb5.conf contents:" in stdout
        assert "default_realm = D.LOCAL" in stdout
        assert "[*] Command: /usr/bin/firefox --profile" in stdout
        assert "[*]   KRB5_TRACE=/dev/stderr" in stdout

    def test_a_non_verbose_launch_prints_nothing(self, tmp_path, capsys):
        # The control that keeps the fix from leaking narration into the quiet path.
        krb5 = tmp_path / "krb5.conf"
        krb5.write_text("[libdefaults]\n")
        proc = MagicMock()
        proc.wait.return_value = 0
        with patch(
            "seamless_sso_browser.launcher.subprocess.Popen", return_value=proc
        ), patch("seamless_sso_browser.launcher.signal.signal"):
            launch_firefox(
                firefox_path="/usr/bin/firefox",
                profile_dir=str(tmp_path / "profile"),
                ccache_path=str(tmp_path / "x.ccache"),
                krb5_conf_path=str(krb5),
                target_url="https://example.com",
                verbose=False,
            )

        assert capsys.readouterr().out == ""

    def test_the_default_verbose_block_names_no_okta(self, tmp_path, capsys):
        # idp defaults to IDP_AZURE, so a call that omits it is the Azure launch.
        # Read the register rather than restating it.
        stdout = self._verbose_stdout(tmp_path, capsys)

        leaked = [t for t in errors.forbidden_terms(errors.IDP_AZURE) if t in stdout]
        assert not leaked, f"the Azure --verbose block names {leaked}"

    def test_the_azure_block_still_explains_the_ntlm_fallback(self, tmp_path, capsys):
        # The positive half: dropping the Okta sentence must not drop the advice.
        stdout = self._verbose_stdout(tmp_path, capsys)

        assert "NTLM" in stdout
        assert "fell back" in stdout

    def test_an_explicit_okta_launch_keeps_the_precheckfailure_hint(self, tmp_path, capsys):
        # The Okta half of the register: this is the one place precheckFailure belongs.
        stdout = self._verbose_stdout(tmp_path, capsys, idp="okta")

        assert "Okta precheckFailure" in stdout
        leaked = [t for t in errors.forbidden_terms(errors.IDP_OKTA) if t in stdout]
        assert not leaked, f"the Okta --verbose block names {leaked}"

    def test_an_explicit_azure_launch_matches_the_default(self, tmp_path, capsys):
        # Omitting idp and passing idp="azure" must produce the same output, or the
        # default is not what S2-R20 says it is. The default protects the callers that
        # do not pass idp -- TestLaunchFirefoxEnv's three, and any caller outside this
        # repository; cli.py itself passes idp=args.idp explicitly.
        default_out = self._verbose_stdout(tmp_path, capsys)
        explicit_out = self._verbose_stdout(tmp_path, capsys, idp="azure")

        assert default_out == explicit_out
        assert "Seamless SSO did not fire" in default_out

    def test_the_shared_advice_is_not_duplicated_into_both_branches(self, tmp_path, capsys):
        # One shared sentence, one branched one -- not the same bug in a new shape.
        stdout = self._verbose_stdout(tmp_path, capsys, idp="okta")

        assert stdout.count("Watch for a Kerberos ticket") == 1


class TestLaunchFailures:
    """C5: the two ways a launch used to fail without saying anything usable.

    find_firefox checked os.path.isfile only, so a --firefox-path pointing at a file that
    exists but cannot be executed was accepted; and Popen was unwrapped, so when exec did
    fail the OSError escaped launch_firefox raw. Both now raise LocalEnvironmentError from
    launcher.py, and these tests pin the reason each one names.
    """

    def test_a_non_executable_firefox_is_rejected_at_the_gate(self, tmp_path):
        shim = tmp_path / "firefox"
        shim.write_text("#!/bin/sh\n")
        shim.chmod(0o644)
        with pytest.raises(LocalEnvironmentError) as excinfo:
            find_firefox(str(shim))
        assert excinfo.value.exit_code == 1
        message = str(excinfo.value)
        assert str(shim) in message
        # A third condition with its own text: the two frozen not-found messages are
        # pinned by == elsewhere in this file and must not be reused for this case.
        assert "not found" not in message

    def test_the_gate_names_the_not_executable_reason(self, tmp_path):
        # The reason above the gate is a specific one, not merely some launch failure:
        # only this branch knows the file was never executable, and the four exec-time
        # reasons all read as though exec had been attempted.
        shim = tmp_path / "firefox"
        shim.write_text("#!/bin/sh\n")
        shim.chmod(0o644)

        with pytest.raises(LocalEnvironmentError) as excinfo:
            find_firefox(str(shim))

        assert errors.FIREFOX_REASON_NOT_EXECUTABLE in str(excinfo.value)

    def test_a_popen_oserror_becomes_a_local_environment_error(self, tmp_path):
        # Popen raises before signal.signal is reached, so no signal patch is needed, and
        # verbose=False keeps the --verbose block from opening krb5_conf_path.
        with patch(
            "seamless_sso_browser.launcher.subprocess.Popen",
            side_effect=PermissionError(13, "Permission denied"),
        ), pytest.raises(LocalEnvironmentError) as excinfo:
            launch_firefox(
                firefox_path="/usr/bin/firefox",
                profile_dir=str(tmp_path / "profile"),
                ccache_path=str(tmp_path / "x.ccache"),
                krb5_conf_path=str(tmp_path / "krb5.conf"),
                target_url="https://example.com",
                verbose=False,
            )
        assert excinfo.value.exit_code == 1
        assert "/usr/bin/firefox" in str(excinfo.value)

    def _failure_from_popen(self, tmp_path, err):
        """Drive launch_firefox with Popen raising err, and hand back what it raised."""
        with patch(
            "seamless_sso_browser.launcher.subprocess.Popen", side_effect=err
        ), pytest.raises(LocalEnvironmentError) as excinfo:
            launch_firefox(
                firefox_path="/usr/bin/firefox",
                profile_dir=str(tmp_path / "profile"),
                ccache_path=str(tmp_path / "x.ccache"),
                krb5_conf_path=str(tmp_path / "krb5.conf"),
                target_url="https://example.com",
                verbose=False,
            )
        return excinfo.value

    @pytest.mark.parametrize(
        ("code", "reason"),
        [
            (errno.ENOENT, errors.FIREFOX_REASON_MISSING),
            (errno.ENOEXEC, errors.FIREFOX_REASON_EXEC_FORMAT),
            (errno.EACCES, errors.FIREFOX_REASON_PERMISSION),
            (errno.EPERM, errors.FIREFOX_REASON_PERMISSION),
            # ENOMEM is deliberately unmapped: it proves the default branch, which is what
            # keeps an errno nobody anticipated from raising inside the error path.
            (errno.ENOMEM, errors.FIREFOX_REASON_OTHER),
            (None, errors.FIREFOX_REASON_OTHER),
        ],
    )
    def test_each_exec_errno_names_its_own_reason(self, tmp_path, code, reason):
        error = self._failure_from_popen(tmp_path, OSError(code, "whatever the OS said"))

        assert reason in str(error)

    def test_the_launch_failure_message_carries_no_os_text(self, tmp_path):
        # No OS-provided text is interpolated into a user-facing message in this project,
        # which is why every reason is a module constant.
        error = self._failure_from_popen(tmp_path, OSError(errno.ENOEXEC, "Exec format error"))

        assert "Exec format error" not in str(error)

    def test_a_launch_failure_chains_the_cause(self, tmp_path):
        # The cause chain is what --verbose prints, and B904 only checks that something
        # was chained -- not that it was the exception that actually failed.
        original = OSError(errno.ENOEXEC, "Exec format error")

        error = self._failure_from_popen(tmp_path, original)

        assert error.__cause__ is original
