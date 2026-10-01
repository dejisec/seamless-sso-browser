import argparse
import importlib.util
import os
import subprocess
import sys
from contextlib import ExitStack
from unittest.mock import MagicMock, patch

import pytest
from impacket.krb5.ccache import CCache

from seamless_sso_browser.cli import main


class _RealSentinel:
    """Type of the REAL sentinel; its repr names it in a test failure."""

    def __repr__(self) -> str:
        return "REAL"


REAL = _RealSentinel()


def _load_ticketer_class():
    """Load TICKETER class from impacket's installed ticketer.py script."""
    ticketer_path = os.path.join(
        os.path.dirname(sys.executable),
        "ticketer.py",
    )
    if os.path.isfile(ticketer_path):
        spec = importlib.util.spec_from_file_location("_ticketer", ticketer_path)
        ticketer_mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(ticketer_mod)
        return ticketer_mod.TICKETER
    from impacket.examples.ticketer import TICKETER

    return TICKETER


def make_dummy_ccache(path: str, spn: str) -> None:
    """Create a minimal ccache file by forging a ticket with impacket."""
    TICKETER = _load_ticketer_class()

    options = argparse.Namespace(
        spn=spn,
        domain_sid="S-1-5-21-1111111111-2222222222-3333333333",
        user_id="1000",
        nthash="a" * 32,
        aesKey=None,
        groups="513",
        duration="1",
        extra_sid=None,
        extra_pac=True,
        old_pac=False,
        impersonate=None,
        request=False,
        user=None,
        password=None,
        hashes=None,
        keytab=None,
        dc_ip=None,
        domain=None,
        ts=False,
        debug=False,
    )

    work_dir = os.path.dirname(path)
    original_cwd = os.getcwd()
    os.chdir(work_dir)
    try:
        TICKETER("testuser", "", "test.local", options).run()
        os.rename(os.path.join(work_dir, "testuser.ccache"), path)
    finally:
        os.chdir(original_cwd)


def make_dummy_kirbi(ccache_path: str, kirbi_path: str) -> None:
    """Convert a ccache file to kirbi (KRB-CRED) format for testing."""
    ccache = CCache.loadFile(ccache_path)
    kirbi_data = ccache.toKRBCRED()
    with open(kirbi_path, "wb") as f:
        f.write(kirbi_data)


def make_empty_ccache(source_ccache_path: str, path: str) -> None:
    """Write a ccache with a valid header and zero credentials, from an existing one.

    What --ccache's credential check and the ticket-kind checks are held to: the
    header parses, so CCache(data) succeeds, and credentials is empty, so
    credentials[0] would raise IndexError.
    """
    ccache = CCache.loadFile(source_ccache_path)
    ccache.credentials = []
    ccache.saveFile(path)


def _default_cli_patches() -> dict[str, object]:
    """Build the default replacements run_main installs on seamless_sso_browser.cli.

    Built per call, so one test's call history never reaches another's mocks.
    """
    return {
        "find_firefox": MagicMock(return_value="/usr/bin/firefox"),
        "forge_tickets": MagicMock(return_value="/tmp/combined.ccache"),
        "create_firefox_profile": MagicMock(return_value="/tmp/profile"),
        "create_krb5_conf": MagicMock(return_value="/tmp/krb5.conf"),
        "launch_firefox": MagicMock(),
        "cleanup": MagicMock(),
        "tgs_from_credentials": MagicMock(return_value="/tmp/creds.ccache"),
        "tgs_from_tgt": MagicMock(return_value="/tmp/tgt.ccache"),
    }


def run_main(
    argv: list[str],
    capsys: pytest.CaptureFixture[str],
    **patches: object,
) -> tuple[int, str, str]:
    """Run cli.main() in process with patched externals, returning (exit_code, stdout, stderr).

    sys.argv becomes ["seamless-sso-browser", *argv]; main() reads sys.argv[1:] itself.

    Eight names are patched by default, each at seamless_sso_browser.cli.<name> — the point
    of use, never the defining module — with these return values:

        find_firefox            -> "/usr/bin/firefox"
        forge_tickets           -> "/tmp/combined.ccache"
        create_firefox_profile  -> "/tmp/profile"
        create_krb5_conf        -> "/tmp/krb5.conf"
        launch_firefox          -> a bare MagicMock
        cleanup                 -> a bare MagicMock
        tgs_from_credentials    -> "/tmp/creds.ccache"
        tgs_from_tgt            -> "/tmp/tgt.ccache"

    tempfile.mkdtemp is deliberately not patched, so main() creates a real temp directory.

    Each **patches key is an attribute name on seamless_sso_browser.cli, and its value is
    used as the replacement object itself: it replaces the default replacement when the name
    is one of the eight, and adds a patch when it is not. So
    run_main(argv, capsys, find_firefox=MagicMock(side_effect=OSError)) makes that boundary
    fail, and parse_user_sid=MagicMock(return_value=("S-1-5-21-1-2-3", 4)) patches a name the
    default set leaves alone.

    The REAL sentinel is the exception: a value of REAL means do not patch that name at all,
    so the genuine function runs. It removes the name from the default set if it is there and
    does nothing if it is not, which is how run_main(argv, capsys, cleanup=REAL) exercises the
    real cleanup through main().

    SystemExit is the only exception caught: its code is returned, with None read as 0, and a
    normal return from main() is 0 too. Anything else raised below main() propagates out of
    run_main, so a caller that wants to observe a raise wraps run_main in pytest.raises.
    """
    replacements = _default_cli_patches()
    for name, replacement in patches.items():
        if replacement is REAL:
            replacements.pop(name, None)
        else:
            replacements[name] = replacement

    exit_code = 0
    with ExitStack() as stack:
        stack.enter_context(patch("sys.argv", ["seamless-sso-browser", *argv]))
        for name, replacement in replacements.items():
            stack.enter_context(patch(f"seamless_sso_browser.cli.{name}", new=replacement))
        try:
            main()
        except SystemExit as exc:
            exit_code = 0 if exc.code is None else exc.code

    captured = capsys.readouterr()
    return exit_code, captured.out, captured.err


def run_main_subprocess(
    argv: list[str], *, timeout: float = 30.0
) -> subprocess.CompletedProcess[str]:
    """Run cli.main() in a real process, returning the CompletedProcess unexamined.

    run_main drives main() in process, where a SystemExit never reaches the interpreter's
    traceback printer, so "no traceback was printed" cannot be observed there at all.
    Only a real process distinguishes a working handler from a harness that cannot see
    tracebacks, which is what this layer exists for: the exit code, the stdout/stderr
    split, the message body, and the presence or absence of a traceback.

    The command is
    [sys.executable, "-c", "from seamless_sso_browser.cli import main; main()", *argv],
    captured as text. python -m seamless_sso_browser is deliberately not used: this project
    has no __main__.py, and adding one so that a test could use it would grow the public
    surface for the test's convenience. No PYTHONPATH, env= or cwd= help is
    needed either — sys.executable under uv run pytest is the project venv's interpreter,
    which already has seamless_sso_browser installed, and the --help case proves it.

    Usage text is not a caveat here. sys.argv[0] is "-c" in this subprocess, but parse_args
    passes prog="seamless-sso-browser" to ArgumentParser explicitly, so argparse never
    consults sys.argv[0]: usage text names seamless-sso-browser here exactly as it does in
    process. Assertions may read usage and prog text freely.

    The timeout makes a hung subprocess fail the test rather than hang the suite; 30 s is
    generous for a path that never reaches a network.

    A non-zero exit is the subject of most of these tests, so check=True is not used and
    nothing is raised on one. Callers read .returncode, .stdout and .stderr themselves.
    """
    return subprocess.run(
        [sys.executable, "-c", "from seamless_sso_browser.cli import main; main()", *argv],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
