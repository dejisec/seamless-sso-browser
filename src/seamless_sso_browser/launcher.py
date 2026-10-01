"""Firefox launch, environment setup, and cleanup."""

import errno
import os
import shutil
import signal
import subprocess

from seamless_sso_browser.errors import (
    FIREFOX_REASON_EXEC_FORMAT,
    FIREFOX_REASON_MISSING,
    FIREFOX_REASON_NOT_EXECUTABLE,
    FIREFOX_REASON_OTHER,
    FIREFOX_REASON_PERMISSION,
    IDP_AZURE,
    IDP_OKTA,
    LocalEnvironmentError,
    firefox_launch_message,
)


def find_firefox(firefox_path: str | None) -> str:
    if firefox_path:
        if not os.path.isfile(firefox_path):
            raise LocalEnvironmentError(f"Firefox not found at {firefox_path}")
        if not os.access(firefox_path, os.X_OK):
            raise LocalEnvironmentError(
                firefox_launch_message(firefox_path, reason=FIREFOX_REASON_NOT_EXECUTABLE)
            )
        return firefox_path

    # No executable check after the PATH lookup: shutil.which already tests
    # os.access(fn, os.F_OK | os.X_OK), so one here could never fire.
    found = shutil.which("firefox") or shutil.which("firefox-esr")
    if not found:
        raise LocalEnvironmentError(
            "Firefox not found on PATH.\nInstall with: sudo apt install firefox-esr"
        )
    return found


def cleanup(temp_dir: str, ccache_path: str | None = None) -> None:
    if os.path.isdir(temp_dir):
        shutil.rmtree(temp_dir, ignore_errors=True)
    if ccache_path and os.path.isfile(ccache_path):
        os.unlink(ccache_path)


_LAUNCH_REASONS_BY_ERRNO = {
    errno.ENOENT: FIREFOX_REASON_MISSING,
    errno.ENOEXEC: FIREFOX_REASON_EXEC_FORMAT,
    errno.EACCES: FIREFOX_REASON_PERMISSION,
    errno.EPERM: FIREFOX_REASON_PERMISSION,
}


def _launch_failure_reason(err: OSError) -> str:
    """Map an exec-time OSError to the reason firefox_launch_message renders."""
    # err.errno, never err.strerror: no OS-provided text reaches a user-facing message.
    # .get cannot raise, so an unmapped errno -- including None -- still gets a reason
    # rather than a traceback in the middle of error handling.
    return _LAUNCH_REASONS_BY_ERRNO.get(err.errno, FIREFOX_REASON_OTHER)


def launch_firefox(
    firefox_path: str,
    profile_dir: str,
    ccache_path: str,
    krb5_conf_path: str,
    target_url: str,
    verbose: bool = False,
    idp: str = IDP_AZURE,
) -> None:
    env = os.environ.copy()
    env["KRB5CCNAME"] = ccache_path
    env["KRB5_CONFIG"] = krb5_conf_path
    if verbose:
        env["KRB5_TRACE"] = "/dev/stderr"
        env["NSPR_LOG_MODULES"] = "negotiateauth:5"

    cmd = [firefox_path, "--profile", profile_dir, "--no-remote", target_url]

    if verbose:
        print(f"[*] KRB5CCNAME={ccache_path}")
        print(f"[*] KRB5_CONFIG={krb5_conf_path}")
        print(f"[*] Profile: {profile_dir}")
        print(f"[*] Command: {' '.join(cmd)}")
        print("[*] krb5.conf contents:")
        with open(krb5_conf_path) as f:
            for line in f:
                print(f"    {line}", end="")
        print()
        print("[*] Tracing enabled for this run (Firefox stderr):")
        print("[*]   NSPR_LOG_MODULES=negotiateauth:5")
        print("[*]   KRB5_TRACE=/dev/stderr")
        print("[*] Watch for a Kerberos ticket for the SSO SPN pulled from the")
        print("[*] ccache; a raw NTLM token means the negotiation fell back")
        if idp == IDP_OKTA:
            print("[*] (which would trigger Okta precheckFailure).")
        else:
            print("[*] (so Seamless SSO did not fire).")

    stderr_dest = None if verbose else subprocess.DEVNULL
    # The try body is this Popen call alone, and that scoping is the point: KdcUnreachableError
    # is an OSError, so a wider body could catch an error raised elsewhere in this project and
    # relabel it as a failure to launch Firefox.
    try:
        proc = subprocess.Popen(cmd, env=env, stderr=stderr_dest)
    except OSError as err:
        raise LocalEnvironmentError(
            firefox_launch_message(firefox_path, reason=_launch_failure_reason(err))
        ) from err

    def _signal_handler(signum, frame):
        proc.terminate()

    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    proc.wait()
