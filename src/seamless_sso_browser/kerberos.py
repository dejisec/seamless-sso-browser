"""DC-interactive Kerberos operations and ticket format parsing."""

import base64
import datetime
import os
import random

from impacket.krb5 import constants
from impacket.krb5.asn1 import (
    AP_REQ,
    AS_REP,
    TGS_REP,
    TGS_REQ,
    Authenticator,
    EncTGSRepPart,
    seq_set,
    seq_set_iter,
)
from impacket.krb5.ccache import CCache
from impacket.krb5.crypto import Key
from impacket.krb5.kerberosv5 import getKerberosTGT, sendReceive
from impacket.krb5.types import KerberosTime, Principal, Ticket
from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue

from seamless_sso_browser.forger import merge_ccaches

try:
    _rand = random.SystemRandom()
except NotImplementedError:
    _rand = random


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


def _get_tgs(server_name, domain, kdc_host, tgt, cipher, session_key):
    """Request a TGS without the canonicalize KDC option.

    Impacket's getKerberosTGS sets canonicalize, which causes the KDC to
    issue cross-realm referrals for SPNs whose hostname belongs to a
    different DNS domain (e.g. the Azure SSO SPNs). It then follows the
    referral back to the same kdcHost, which fails with
    KDC_ERR_WRONG_REALM.
    """
    try:
        decoded_tgt = decoder.decode(tgt, asn1Spec=AS_REP())[0]
    except Exception:
        decoded_tgt = decoder.decode(tgt, asn1Spec=TGS_REP())[0]

    domain = domain.upper()

    ticket = Ticket()
    ticket.from_asn1(decoded_tgt['ticket'])

    ap_req = AP_REQ()
    ap_req['pvno'] = 5
    ap_req['msg-type'] = int(constants.ApplicationTagNumbers.AP_REQ.value)
    ap_req['ap-options'] = constants.encodeFlags([])
    seq_set(ap_req, 'ticket', ticket.to_asn1)

    authenticator = Authenticator()
    authenticator['authenticator-vno'] = 5
    authenticator['crealm'] = decoded_tgt['crealm'].asOctets()

    client_name = Principal()
    client_name.from_asn1(decoded_tgt, 'crealm', 'cname')
    seq_set(authenticator, 'cname', client_name.components_to_asn1)

    now = datetime.datetime.now(datetime.UTC)
    authenticator['cusec'] = now.microsecond
    authenticator['ctime'] = KerberosTime.to_asn1(now)

    encoded_authenticator = encoder.encode(authenticator)
    encrypted_authenticator = cipher.encrypt(
        session_key, 7, encoded_authenticator, None
    )

    ap_req['authenticator'] = noValue
    ap_req['authenticator']['etype'] = cipher.enctype
    ap_req['authenticator']['cipher'] = encrypted_authenticator

    encoded_ap_req = encoder.encode(ap_req)

    tgs_req = TGS_REQ()
    tgs_req['pvno'] = 5
    tgs_req['msg-type'] = int(constants.ApplicationTagNumbers.TGS_REQ.value)
    tgs_req['padata'] = noValue
    tgs_req['padata'][0] = noValue
    tgs_req['padata'][0]['padata-type'] = int(
        constants.PreAuthenticationDataTypes.PA_TGS_REQ.value
    )
    tgs_req['padata'][0]['padata-value'] = encoded_ap_req

    req_body = seq_set(tgs_req, 'req-body')

    opts = [
        constants.KDCOptions.forwardable.value,
        constants.KDCOptions.renewable.value,
        constants.KDCOptions.renewable_ok.value,
    ]
    req_body['kdc-options'] = constants.encodeFlags(opts)
    seq_set(req_body, 'sname', server_name.components_to_asn1)
    req_body['realm'] = domain

    till = datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=1)
    req_body['till'] = KerberosTime.to_asn1(till)
    req_body['nonce'] = _rand.getrandbits(31)
    seq_set_iter(req_body, 'etype', (
        int(constants.EncryptionTypes.rc4_hmac.value),
        int(constants.EncryptionTypes.des3_cbc_sha1_kd.value),
        int(constants.EncryptionTypes.des_cbc_md5.value),
        int(cipher.enctype),
    ))

    message = encoder.encode(tgs_req)
    r = sendReceive(message, domain, kdc_host)

    tgs = decoder.decode(r, asn1Spec=TGS_REP())[0]
    cipher_text = tgs['enc-part']['cipher']
    plain_text = cipher.decrypt(session_key, 8, cipher_text)
    enc_part = decoder.decode(plain_text, asn1Spec=EncTGSRepPart())[0]

    new_session_key = Key(
        enc_part['key']['keytype'],
        enc_part['key']['keyvalue'].asOctets(),
    )

    return r, cipher, session_key, new_session_key


def _save_tgs_as_ccache(tgs, old_session_key, session_key, path: str) -> None:
    """Save a TGS response as a ccache file."""
    ccache = CCache()
    ccache.fromTGS(tgs, old_session_key, session_key)
    ccache.saveFile(path)


def _request_tgs_for_spns(
    domain: str, dc_ip: str, tgt, cipher, session_key, work_dir: str,
    spns: list[str] | None = None,
) -> str:
    """Request TGS for given SPNs and return path to ccache.

    When *spns* is None, defaults to the two Azure AD SSO SPNs and merges them.
    A single SPN returns the ccache directly (no merge).  Multiple SPNs are
    merged and temps cleaned up.
    """
    if spns is None:
        from seamless_sso_browser.forger import AADG_SPN, AUTOLOGON_SPN
        spns = [AUTOLOGON_SPN, AADG_SPN]

    paths = []
    for i, spn_str in enumerate(spns):
        server_name = Principal(
            spn_str, type=constants.PrincipalNameType.NT_SRV_INST.value
        )
        tgs, _, old_key, new_key = _get_tgs(
            server_name, domain, dc_ip, tgt, cipher, session_key
        )
        path = os.path.join(work_dir, f"tgs_{i}.ccache")
        _save_tgs_as_ccache(tgs, old_key, new_key, path)
        paths.append(path)

    if len(paths) == 1:
        return paths[0]

    combined = os.path.join(work_dir, "combined.ccache")
    merge_ccaches(paths[0], paths[1], combined)
    os.unlink(paths[0])
    os.unlink(paths[1])
    return combined


def tgs_from_tgt(
    tgt_value: str, domain: str, dc_ip: str, work_dir: str,
    spns: list[str] | None = None,
) -> str:
    """Load a TGT from file/base64, request TGS for SSO SPNs from DC."""
    ccache = load_ticket(tgt_value)
    tgt_data = ccache.credentials[0].toTGT()
    return _request_tgs_for_spns(
        domain, dc_ip,
        tgt_data["KDC_REP"], tgt_data["cipher"], tgt_data["sessionKey"],
        work_dir, spns=spns,
    )


def tgs_from_credentials(
    domain: str,
    dc_ip: str,
    username: str,
    work_dir: str,
    password: str | None = None,
    nthash: str | None = None,
    aes_key: str | None = None,
    spns: list[str] | None = None,
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

    return _request_tgs_for_spns(
        domain, dc_ip, tgt, cipher, session_key, work_dir, spns=spns,
    )
