import argparse
import importlib.util
import os
import sys

from impacket.krb5.ccache import CCache


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
