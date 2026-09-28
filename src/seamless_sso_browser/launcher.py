"""Firefox launch, environment setup, and cleanup."""

import os
import shutil
import signal
import subprocess
import sys


def find_firefox(firefox_path: str | None) -> str:
    if firefox_path:
        if not os.path.isfile(firefox_path):
            print(f"Error: Firefox not found at {firefox_path}", file=sys.stderr)
            sys.exit(1)
        return firefox_path

    found = shutil.which("firefox") or shutil.which("firefox-esr")
    if not found:
        print(
            "Error: Firefox not found on PATH.\nInstall with: sudo apt install firefox-esr",
            file=sys.stderr,
        )
        sys.exit(1)
    return found


def cleanup(temp_dir: str, ccache_path: str | None = None) -> None:
    if os.path.isdir(temp_dir):
        shutil.rmtree(temp_dir, ignore_errors=True)
    if ccache_path and os.path.isfile(ccache_path):
        os.unlink(ccache_path)


def launch_firefox(
    firefox_path: str,
    profile_dir: str,
    ccache_path: str,
    krb5_conf_path: str,
    target_url: str,
    verbose: bool = False,
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
        print("[*] ccache; a raw NTLM token means the negotiation fell back (would")
        print("[*] trigger Okta precheckFailure).")

    stderr_dest = None if verbose else subprocess.DEVNULL
    proc = subprocess.Popen(cmd, env=env, stderr=stderr_dest)

    def _signal_handler(signum, frame):
        proc.terminate()

    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    proc.wait()
