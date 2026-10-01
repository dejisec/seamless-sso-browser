"""DC-interactive Kerberos operations and ticket format parsing."""

import base64
import datetime
import errno
import os
import random
import socket

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
from impacket.krb5.kerberosv5 import KerberosError, getKerberosTGT, sendReceive
from impacket.krb5.types import KerberosTime, Principal, Ticket
from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue

from seamless_sso_browser.errors import (
    KDC_REASON_DNS,
    KDC_REASON_OTHER,
    KDC_REASON_REFUSED,
    KDC_REASON_TIMEOUT,
    TICKET_REASON_DIRECTORY,
    TICKET_REASON_MISSING,
    TICKET_REASON_UNREADABLE,
    TICKET_REASON_UNREADABLE_OTHER,
    KdcProtocolError,
    KdcUnreachableError,
    SsoError,
    TicketError,
    kdc_unreachable_message,
    ticket_file_message,
)
from seamless_sso_browser.forger import merge_ccaches

try:
    _rand = random.SystemRandom()
except NotImplementedError:
    _rand = random


def _looks_like_a_missing_file(value: str) -> bool:
    """True when value is a path to a file that does not exist, rather than base64.

    The rule that keeps two pinned classifications intact: a value whose parent
    directory exists and is not the filesystem root is a path, so a missing file is
    reported as a missing file. "/nonexistent/path/to/file.ccache" has no parent
    directory, and "///not-base64-and-not-a-path!!!" has "///", whose rstrip("/") is
    empty -- both fall through to the base64 branch and keep the messages their tests
    pin. Base64 of a real ticket does contain "/" characters, often near its end; what
    keeps it out of this branch is that the prefix up to its last "/" is a long run of
    base64 characters and not an existing directory, so it falls through too.
    """
    parent = os.path.dirname(value)
    return os.path.isdir(parent) and parent.rstrip("/") != ""


def _unreadable_reason(err: OSError) -> str:
    """Pick the reason for a ticket file the OS refused to hand over.

    Chosen from errno rather than from err.strerror, so no OS text is interpolated
    into a user-facing message -- the same rule that makes
    unexpected_failure_message withhold str(exc).
    """
    if err.errno in (errno.EACCES, errno.EPERM):
        return TICKET_REASON_UNREADABLE
    return TICKET_REASON_UNREADABLE_OTHER


def load_ticket(value: str) -> CCache:
    """Load a Kerberos ticket from a file path (ccache/kirbi) or base64 string."""
    if os.path.isdir(value):
        raise TicketError(ticket_file_message(value, reason=TICKET_REASON_DIRECTORY))

    if os.path.isfile(value):
        try:
            with open(value, "rb") as f:
                data = f.read()
        except OSError as err:
            raise TicketError(
                ticket_file_message(value, reason=_unreadable_reason(err))
            ) from err
    elif _looks_like_a_missing_file(value):
        raise TicketError(ticket_file_message(value, reason=TICKET_REASON_MISSING))
    else:
        try:
            data = base64.b64decode(value, validate=True)
        except Exception as err:
            raise TicketError(
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
        raise TicketError("Invalid ticket: not a valid ccache or kirbi format") from err


def ticket_service_principals(ccache: CCache) -> list[str]:
    """List the service principal of every credential in a loaded ticket.

    Pure: prints nothing, raises nothing, and returns [] for a ccache with no
    credentials -- the caller decides whether that is a failure. prettyPrint()
    returns bytes, and the realm suffix after "@" is part of what it returns
    (b'HTTP/autologon.microsoftazuread-sso.com@TEST.LOCAL'), so a caller matching
    against a bare SPN has to split it off itself.
    """
    principals: list[str] = []
    for credential in ccache.credentials:
        server = credential['server'].prettyPrint()
        if isinstance(server, bytes):
            server = server.decode("utf-8", errors="replace")
        principals.append(server)
    return principals


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


_KDC_PORT = 88  # impacket's sendReceive default; this CLI exposes no way to change it.


def _kdc_unreachable_reason(err: OSError) -> str:
    """Pick the reason a KDC connection failed, from the errno nested in args[1].

    impacket raises socket.error("Connection error (host:port)", inner), and a
    two-argument OSError takes args[0] as its errno -- so the outer .errno is that
    message string and the real errno is on the inner exception. gaierror and
    TimeoutError are matched by type: gaierror's errno is EAI_NONAME (8), which as an
    OS errno means ENOEXEC, and a connect timeout often carries no errno at all.
    """
    inner = err.args[1] if len(err.args) > 1 else None
    if isinstance(inner, socket.gaierror):
        return KDC_REASON_DNS
    if isinstance(inner, TimeoutError):
        return KDC_REASON_TIMEOUT
    code = getattr(inner, "errno", None)
    if code == errno.ECONNREFUSED:
        return KDC_REASON_REFUSED
    if code == errno.ETIMEDOUT:
        return KDC_REASON_TIMEOUT
    return KDC_REASON_OTHER


def _kdc_unreachable(err: OSError, *, dc_ip: str) -> KdcUnreachableError:
    """Translate a socket failure from impacket into the typed exit-4 failure."""
    return KdcUnreachableError(
        kdc_unreachable_message(
            f"{dc_ip}:{_KDC_PORT}", reason=_kdc_unreachable_reason(err)
        )
    )


# The impacket exception types that mean "the KDC answered, and it said no". Published
# so cli.py can catch one at its own boundary without importing anything from impacket:
# the coupling stays in this module, which is the only one that already has it.
IMPACKET_KDC_ERRORS: tuple[type[BaseException], ...] = (KerberosError,)

# Carried when impacket has no description for the code. cli.py replaces the message with
# the register-correct row and passes this text through as that row's detail, so it reaches
# the user only on a code errors.py does not map -- where a short neutral line after the
# number beats leaving the number bare.
_KDC_PROTOCOL_FALLBACK = "the KDC rejected the request"


def _kdc_error_code_name(code: int) -> str | None:
    """Resolve a KRB5 error code to its constants.ErrorCodes name, or None.

    Matched against the enum rather than parsed out of impacket's message text, and it
    cannot raise: constants.ErrorCodes(code) raises ValueError for a code the installed
    impacket does not know, and an unmapped code still has to produce a clean message.
    """
    for member in constants.ErrorCodes:
        if member.value == code:
            return member.name
    return None


def _kdc_error_detail(err: KerberosError) -> str:
    """impacket's own description of a KRB5 error code, or "" when it has none.

    getErrorString() returns a (name, description) tuple and raises KeyError for a code
    outside its table, so both are guarded. A failure here would be a traceback in the
    middle of error handling. Nothing about the swallowed exception is printed or
    interpolated -- the credential-path prohibition is on surfacing impacket's
    internals, and this does the opposite.
    """
    try:
        described = err.getErrorString()
    except Exception:
        return ""
    if isinstance(described, tuple):
        described = described[-1] if described else ""
    return str(described)


def kdc_protocol_error(err: KerberosError) -> KdcProtocolError:
    """Translate a KerberosError from the KDC into the typed exit-5 failure.

    The message it carries is impacket's neutral description; cli.py re-renders it in
    the register the run chose, because --idp is known there and nowhere here.
    """
    code = err.getErrorCode()
    return KdcProtocolError(
        _kdc_error_detail(err) or _KDC_PROTOCOL_FALLBACK,
        code=code,
        code_name=_kdc_error_code_name(code),
    )


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
        try:
            tgs, _, old_key, new_key = _get_tgs(
                server_name, domain, dc_ip, tgt, cipher, session_key
            )
        except SsoError:
            raise
        except IMPACKET_KDC_ERRORS as err:
            raise kdc_protocol_error(err) from err
        except OSError as err:
            raise _kdc_unreachable(err, dc_ip=dc_ip) from err
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
    try:
        tgt, cipher, _, session_key = getKerberosTGT(
            user_principal, password or "", domain, lmhash_bytes, nthash_bytes,
            aes_key, dc_ip,
        )
    except SsoError:
        raise
    except IMPACKET_KDC_ERRORS as err:
        raise kdc_protocol_error(err) from err
    except OSError as err:
        raise _kdc_unreachable(err, dc_ip=dc_ip) from err

    return _request_tgs_for_spns(
        domain, dc_ip, tgt, cipher, session_key, work_dir, spns=spns,
    )
