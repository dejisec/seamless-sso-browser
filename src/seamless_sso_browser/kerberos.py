"""DC-interactive Kerberos operations and ticket format parsing."""

import base64
import os

from impacket.krb5 import constants
from impacket.krb5.ccache import CCache
from impacket.krb5.kerberosv5 import getKerberosTGS, getKerberosTGT
from impacket.krb5.types import Principal

from seamless_sso_browser.forger import AADG_SPN, AUTOLOGON_SPN, merge_ccaches


def load_ticket(value: str) -> CCache:
    """Load a Kerberos ticket from a file path (ccache/kirbi) or base64 string."""
    if os.path.isfile(value):
        with open(value, "rb") as f:
            data = f.read()
    else:
        try:
            data = base64.b64decode(value, validate=True)
        except Exception as err:
            raise ValueError(
                "Invalid ticket input: not a file path and not valid base64"
            ) from err

    try:
        return CCache(data)
    except Exception:
        pass

    try:
        ccache = CCache()
        ccache.fromKRBCRED(data)
        return ccache
    except Exception as err:
        raise ValueError("Invalid ticket: not a valid ccache or kirbi format") from err


def ccache_from_tgs(tgs_value: str, work_dir: str) -> str:
    """Load a TGS from file/base64 (ccache or kirbi) and save as ccache."""
    ccache = load_ticket(tgs_value)
    output_path = os.path.join(work_dir, "imported.ccache")
    ccache.saveFile(output_path)
    return output_path


def parse_user_sid(sid: str) -> tuple[str, int]:
    """Split a full user SID into (domain_sid, user_rid)."""
    parts = sid.rsplit("-", 1)
    if len(parts) != 2:
        raise ValueError(f"Invalid SID format: {sid}")
    domain_sid, rid_str = parts
    if not domain_sid.startswith("S-1-5-21-"):
        raise ValueError(f"Invalid SID format: {sid}")
    try:
        user_rid = int(rid_str)
    except ValueError as err:
        raise ValueError(f"Invalid RID in SID: {rid_str}") from err
    return domain_sid, user_rid


def _parse_ntlm_hash(hash_str: str) -> tuple[bytes, bytes]:
    """Parse '[LMHASH:]NTHASH' into (lmhash_bytes, nthash_bytes)."""
    if ":" in hash_str:
        lm, nt = hash_str.split(":", 1)
        return bytes.fromhex(lm), bytes.fromhex(nt)
    return b"", bytes.fromhex(hash_str)


def _save_tgs_as_ccache(tgs, old_session_key, session_key, path: str) -> None:
    """Save a TGS response as a ccache file."""
    ccache = CCache()
    ccache.fromTGS(tgs, old_session_key, session_key)
    ccache.saveFile(path)


def _request_tgs_for_spns(
    domain: str, dc_ip: str, tgt, cipher, session_key, work_dir: str
) -> str:
    """Request TGS for both SSO SPNs and return path to merged ccache."""
    paths = []
    for i, spn_str in enumerate([AUTOLOGON_SPN, AADG_SPN]):
        server_name = Principal(
            spn_str, type=constants.PrincipalNameType.NT_SRV_INST.value
        )
        tgs, _, old_key, new_key = getKerberosTGS(
            server_name, domain, dc_ip, tgt, cipher, session_key
        )
        path = os.path.join(work_dir, f"tgs_{i}.ccache")
        _save_tgs_as_ccache(tgs, old_key, new_key, path)
        paths.append(path)

    combined = os.path.join(work_dir, "combined.ccache")
    merge_ccaches(paths[0], paths[1], combined)
    os.unlink(paths[0])
    os.unlink(paths[1])
    return combined


def tgs_from_tgt(tgt_value: str, domain: str, dc_ip: str, work_dir: str) -> str:
    """Load a TGT from file/base64, request TGS for SSO SPNs from DC."""
    ccache = load_ticket(tgt_value)
    tgt_data = ccache.credentials[0].toTGT()
    return _request_tgs_for_spns(
        domain, dc_ip,
        tgt_data["KDC_REP"], tgt_data["cipher"], tgt_data["sessionKey"],
        work_dir,
    )


def tgs_from_credentials(
    domain: str,
    dc_ip: str,
    username: str,
    work_dir: str,
    password: str | None = None,
    nthash: str | None = None,
    aes_key: str | None = None,
) -> str:
    """Authenticate with user credentials, request TGS for SSO SPNs."""
    lmhash_bytes = b""
    nthash_bytes = b""
    if nthash:
        lmhash_bytes, nthash_bytes = _parse_ntlm_hash(nthash)

    user_principal = Principal(
        username, type=constants.PrincipalNameType.NT_PRINCIPAL.value
    )
    tgt, cipher, _, session_key = getKerberosTGT(
        user_principal, password or "", domain, lmhash_bytes, nthash_bytes,
        aes_key, dc_ip,
    )

    return _request_tgs_for_spns(domain, dc_ip, tgt, cipher, session_key, work_dir)
