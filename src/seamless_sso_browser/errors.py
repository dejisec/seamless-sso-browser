"""Exit codes, typed failures, and the IdP-aware message catalogue."""

__all__ = [
    "AZURE_FORBIDDEN_TERMS",
    "EXIT_ENVIRONMENT",
    "EXIT_INTERRUPTED",
    "EXIT_KDC_PROTOCOL",
    "EXIT_KDC_UNREACHABLE",
    "EXIT_OK",
    "EXIT_TICKET",
    "EXIT_USAGE",
    "FIREFOX_REASON_EXEC_FORMAT",
    "FIREFOX_REASON_MISSING",
    "FIREFOX_REASON_NOT_EXECUTABLE",
    "FIREFOX_REASON_OTHER",
    "FIREFOX_REASON_PERMISSION",
    "IDP_AZURE",
    "IDP_OKTA",
    "KDC_REASON_DNS",
    "KDC_REASON_OTHER",
    "KDC_REASON_REFUSED",
    "KDC_REASON_TIMEOUT",
    "KdcProtocolError",
    "KdcUnreachableError",
    "LocalEnvironmentError",
    "NEUTRAL_FORBIDDEN_TERMS",
    "OKTA_FORBIDDEN_TERMS",
    "PATH_REASON_NO_SPACE",
    "PATH_REASON_OTHER",
    "PATH_REASON_PERMISSION",
    "PATH_REASON_READ_ONLY",
    "PATH_WHAT_FIREFOX_PROFILE",
    "PATH_WHAT_KRB5_CONF",
    "SsoError",
    "TICKET_REASON_DIRECTORY",
    "TICKET_REASON_MISSING",
    "TICKET_REASON_NO_CREDENTIALS",
    "TICKET_REASON_UNREADABLE",
    "TICKET_REASON_UNREADABLE_OTHER",
    "TicketError",
    "UsageError",
    "firefox_launch_message",
    "flag_ignored_message",
    "flag_requires_okta_idp_message",
    "forbidden_terms",
    "hex_format_message",
    "interrupted_message",
    "kdc_error_message",
    "kdc_unreachable_message",
    "ntlm_hash_format_message",
    "okta_org_not_derivable_message",
    "sid_format_message",
    "spn_mismatch_message",
    "ticket_file_message",
    "ticket_kind_message",
    "unexpected_failure_message",
    "unwritable_path_message",
]

EXIT_OK = 0
EXIT_ENVIRONMENT = 1
EXIT_USAGE = 2
EXIT_TICKET = 3
EXIT_KDC_UNREACHABLE = 4
EXIT_KDC_PROTOCOL = 5
EXIT_INTERRUPTED = 130  # 128 + SIGINT, for a Ctrl+C before Firefox launched

# The two values --idp takes.
IDP_AZURE = "azure"
IDP_OKTA = "okta"

# The negative half of the IdP messaging contract: a message written for one
# register must never name the other vendor's product, and a message that does
# not depend on the IdP must name neither.
AZURE_FORBIDDEN_TERMS = ("Okta",)
OKTA_FORBIDDEN_TERMS = ("Seamless SSO", "AZUREADSSOACC$")
NEUTRAL_FORBIDDEN_TERMS = ("Okta", "Seamless SSO", "AZUREADSSOACC$")

_FORBIDDEN_TERMS_BY_IDP = {
    IDP_AZURE: AZURE_FORBIDDEN_TERMS,
    IDP_OKTA: OKTA_FORBIDDEN_TERMS,
}


def forbidden_terms(idp: str | None) -> tuple[str, ...]:
    """Terms a message for this IdP must never contain.

    The single source of truth for the register contract's negative half: the
    test suite's register sweep reads it rather than restating the lists. An
    unrecognised value and None both get the strictest list, so a typo or a
    future third IdP fails closed instead of escaping the contract.
    """
    return _FORBIDDEN_TERMS_BY_IDP.get(idp, NEUTRAL_FORBIDDEN_TERMS)


class SsoError(Exception):
    """Raised for any failure this tool recognises, and the base of every type below."""

    # Class-level, so main() can read it off a caught instance or off the class.
    exit_code: int = EXIT_ENVIRONMENT


class UsageError(SsoError, ValueError):
    """Raised for a shape or format problem that reached us outside argparse."""

    exit_code = EXIT_USAGE


class TicketError(SsoError, ValueError):
    """Raised for a missing, unreadable, unparseable, empty or wrong-kind ticket."""

    exit_code = EXIT_TICKET


class KdcUnreachableError(SsoError, OSError):
    """Raised when the KDC refuses the connection, fails to resolve, or times out."""

    # Being an OSError, multi-argument construction would stringify as
    # "[Errno n] text". Construct it from one pre-built message only.
    exit_code = EXIT_KDC_UNREACHABLE


class KdcProtocolError(SsoError):
    """Raised for a Kerberos protocol error returned by the KDC."""

    exit_code = EXIT_KDC_PROTOCOL

    def __init__(
        self,
        message: str,
        *,
        code: int | None = None,
        code_name: str | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.code_name = code_name


class LocalEnvironmentError(SsoError):
    """Raised when Firefox is missing, not executable or not launchable, or a path is unwritable."""

    exit_code = EXIT_ENVIRONMENT


# The shape of the Okta DSSO SPN, for a message written when the real one is not
# known: the CLI builds it as HTTP/<org>.kerberos.<base domain of --okta-domain>.
_OKTA_SPN_SHAPE = "HTTP/<org>.kerberos.<base-domain>"

# code_name -> message, for the KDC errors whose wording does not depend on the
# IdP. Keyed on the name rather than the numeric code or the KDC's own text: the
# impacket floor is >=0.12.0, so its wording can move under us, and a name reads
# in a diff. Only the credential flags are named, never a credential value.
_NEUTRAL_KDC_MESSAGES = {
    "KDC_ERR_WRONG_REALM": (
        "--domain does not match the realm the ticket was issued in; pass the realm "
        "this KDC serves"
    ),
    "KDC_ERR_PREAUTH_FAILED": (
        "the KDC rejected the password, NTLM hash, or AES key for this user; recheck "
        "--password, --user-password-hash, or --user-aes-key"
    ),
    "KDC_ERR_C_PRINCIPAL_UNKNOWN": (
        "--user does not exist in this domain; check the sAMAccountName"
    ),
    "KRB_AP_ERR_SKEW": (
        "the clock skew between this host and the DC is over 5 minutes; synchronize "
        "the clock and retry"
    ),
}


def kdc_error_message(
    code: int,
    idp: str,
    *,
    code_name: str | None = None,
    detail: str = "",
    okta_spn: str | None = None,
) -> str:
    """Build the message for a Kerberos error the KDC returned.

    The caller resolves code_name at the impacket boundary and passes it in, so
    this module needs neither impacket nor impacket's wording. The lookup cannot
    raise: an unmapped code still gets a clean message, built from code_name, or
    from the numeric code when that is None, plus detail when it is non-empty.
    """
    if code_name == "KDC_ERR_S_PRINCIPAL_UNKNOWN":
        # The one row where the two registers genuinely differ.
        if idp == IDP_OKTA:
            return (
                f"the Okta DSSO SPN {okta_spn or _OKTA_SPN_SHAPE} does not exist in this "
                "domain; Agentless Desktop SSO may not be enabled for this org, or "
                "--okta-org/--okta-domain is wrong"
            )
        return (
            "the SSO SPN does not exist in this domain; Seamless SSO may not be enabled "
            "on this tenant, or the AZUREADSSOACC$ account is missing"
        )

    mapped = _NEUTRAL_KDC_MESSAGES.get(code_name)
    if mapped is not None:
        return mapped

    named = code_name if code_name else f"code {code}"
    message = f"the KDC returned Kerberos error {named}"
    return f"{message}; {detail}" if detail else message


def interrupted_message() -> str:
    """Build the message for a Ctrl+C that arrived before Firefox launched."""
    return "interrupted before Firefox launched; nothing is still running"


def unexpected_failure_message(exc: BaseException) -> str:
    """Build the message for a failure no other handler recognised.

    Names the exception's class and nothing else it carries. This is the one
    handler that sees third-party internals, and an exception message from them
    can hold key material; the traceback under --verbose is where the detail
    goes, because the user asked for it there.
    """
    return f"unexpected {type(exc).__name__}; re-run with --verbose for the traceback"


def ticket_kind_message(found_spn: str, *, expected: str) -> str:
    """Build the message for a ticket of the wrong kind, naming both kinds."""
    return f"the ticket is for {found_spn}, but {expected} is required"


# The reasons ticket_file_message renders. Module constants rather than literals at
# the call sites, because cli.py and kerberos.py both report the same failures --
# reached from --ccache in one and from --tgs/--tgt in the other -- and a test
# asserts the sentence by building it from the same constant.
TICKET_REASON_MISSING = "no such file"
TICKET_REASON_DIRECTORY = "it is a directory, not a ticket file"
TICKET_REASON_UNREADABLE = "permission denied"
TICKET_REASON_UNREADABLE_OTHER = "could not be read"
TICKET_REASON_NO_CREDENTIALS = "it holds no credentials"


def ticket_file_message(path: str, *, reason: str, flag: str | None = None) -> str:
    """Build the message for a ticket or ccache file that cannot be used.

    The path is echoed: it is what the operator typed and what they have to fix,
    and a ticket path is not credential material. flag names the flag that carried
    the path when the caller knows it -- kerberos.load_ticket does not, being
    reached from --tgs, --tgt and a base64 value alike.

    TICKET_REASON_UNREADABLE_OTHER exists so an OSError that is not EACCES/EPERM
    still gets an honest reason. The caller picks between the two from err.errno,
    never from err.strerror: no OS text is interpolated into a message, for the
    same reason unexpected_failure_message withholds str(exc).
    """
    named = f"{flag} " if flag else ""
    return f"{named}{path}: {reason}"


# The reasons kdc_unreachable_message renders. The caller picks one from the errno
# on the socket error impacket raises, never from the OS's own strerror -- the same
# rule that keeps OS text out of the TICKET_REASON_* messages.
KDC_REASON_REFUSED = "connection refused"
KDC_REASON_TIMEOUT = "the connection timed out"
KDC_REASON_DNS = "the host name did not resolve"
KDC_REASON_OTHER = "the connection failed"


def kdc_unreachable_message(address: str, *, reason: str) -> str:
    """Build the message for a KDC this host could not reach.

    The address is "<host>:<port>" and the reason is one of the KDC_REASON_*
    constants, so no OS or impacket text is interpolated. --dc-ip is named because it
    is the flag that fixes every one of the four reasons.
    """
    return (
        f"could not reach the KDC at {address} ({reason}). Check --dc-ip and that the "
        "host is routable."
    )


def spn_mismatch_message(found_spns: tuple[str, ...], *, expected: str) -> str:
    """Build the warning for an imported service ticket whose SPN is not the one SSO needs.

    A warning rather than an error, so it says what was found, what was wanted, and
    that the run continues. found_spns carries the realm suffix the ticket actually
    holds, because that is what the operator has to recognise.
    """
    found = ", ".join(found_spns) if found_spns else "none"
    return (
        f"the ticket carries {found}, but {expected} is what this target's SSO needs; "
        "continuing anyway"
    )


def okta_org_not_derivable_message(path: str, *, found_spns: tuple[str, ...]) -> str:
    """Build the error for an Okta run whose ticket carries no host to derive the org from.

    --ccache and --tgs are exempt from requiring --okta-org because the Okta host can
    be read out of the imported ticket. When no credential in it carries an Okta
    Agentless DSSO SPN there is nothing to read, and guessing a host would put a
    dead name in user.js and krb5.conf. found_spns keeps the realm suffix the ticket
    holds, because that is what the operator has to recognise.
    """
    found = ", ".join(found_spns) if found_spns else "none"
    return (
        f"{path} carries no Okta Agentless DSSO service principal, so the Okta host "
        f"cannot be derived from it: found {found}. Pass --okta-org <org>, or use "
        "--idp azure if this is an Azure ticket."
    )


def hex_format_message(flag: str, *, expected_lengths: tuple[int, ...], got_length: int) -> str:
    """Build the message for a credential flag whose value is not hex of a valid length.

    Takes the length received, never the value: the value is key material and
    this message is going to a terminal whose scrollback outlives the process.
    """
    lengths = " or ".join(str(length) for length in expected_lengths)
    return (
        f"{flag} must be hex of {lengths} characters; the value given is "
        f"{got_length} characters"
    )


def sid_format_message(*, got: str) -> str:
    """Build the message for a --user-sid that is not a well-formed SID.

    The one builder in this module that echoes its input: a SID is an identifier
    rather than credential material, and kerberos.parse_user_sid already echoes it
    in its own ValueError.
    """
    return f"--user-sid must look like S-1-5-21-<a>-<b>-<c>-<rid>; got '{got}'."


def ntlm_hash_format_message(flag: str, *, got_length: int) -> str:
    """Build the message for an NTLM-hash flag whose compound shape is wrong.

    Takes the length of the offending half, never the value: --user-password-hash
    carries key material and this message is going to a terminal whose scrollback
    outlives the process.
    """
    return (
        f"{flag} must be [LMHASH:]NTHASH with each half hex of 32 characters; "
        f"the half given is {got_length} characters"
    )


def flag_requires_okta_idp_message(flag: str) -> str:
    """Build the message for a flag or target that only works under --idp okta."""
    return f"{flag} requires --idp okta"


def flag_ignored_message(flag: str, *, because: str) -> str:
    """Build the warning for a flag that parsed fine and has no effect."""
    return f"{flag} is ignored {because}"


# The reasons firefox_launch_message renders. NOT_EXECUTABLE is the one
# launcher.find_firefox's executable gate reports; the other four cover the errnos
# a failing exec raises -- ENOENT, ENOEXEC, EACCES/EPERM, and anything else. The
# caller picks one from err.errno, never from err.strerror: no OS text is
# interpolated into a message, the same rule the TICKET_REASON_* and
# KDC_REASON_* constants follow.
FIREFOX_REASON_NOT_EXECUTABLE = "it is not executable"
FIREFOX_REASON_MISSING = "it no longer exists"
FIREFOX_REASON_EXEC_FORMAT = "it is not a runnable binary on this machine"
FIREFOX_REASON_PERMISSION = "permission denied"
FIREFOX_REASON_OTHER = "it could not be launched"


def firefox_launch_message(path: str, *, reason: str) -> str:
    """Build the message for a Firefox binary that exists but will not launch.

    This is the third Firefox condition and it carries its own wording. The two
    not-found texts launcher.find_firefox raises are frozen, so this one says
    "could not be launched" instead: a reader can tell a Firefox that is absent
    from one that is present and unusable, and neither frozen string is reachable
    through here.

    The path is echoed: it is what --firefox-path carried or what PATH resolved
    to, and a Firefox path is not credential material.
    """
    return f"Firefox at {path} could not be launched: {reason}"


# The two artefacts unwritable_path_message names, and the reasons it renders.
# Both halves are constants rather than literals at the call sites for the reason
# the TICKET_REASON_* constants are: the text has exactly one home, and the tests
# that assert the sentence build it from these names.
PATH_REASON_PERMISSION = "permission denied"
PATH_REASON_READ_ONLY = "the filesystem is read-only"
PATH_REASON_NO_SPACE = "the filesystem is full"
PATH_REASON_OTHER = "it could not be written"

PATH_WHAT_FIREFOX_PROFILE = "the Firefox profile"
PATH_WHAT_KRB5_CONF = "krb5.conf"


def unwritable_path_message(path: str, *, what: str, reason: str) -> str:
    """Build the message for a Firefox profile or krb5.conf that could not be written.

    path is the temp directory, not the file inside it: create_firefox_profile
    builds <temp_dir>/profile and create_krb5_conf writes <temp_dir>/krb5.conf,
    layout that belongs to profile.py and is not restated here. what carries which
    artefact failed; path carries the directory whose filesystem the operator can
    act on, which is the thing they can fix.

    The caller picks the reason from err.errno, never from err.strerror, so no OS
    text is interpolated into the message.
    """
    return f"could not write {what} under {path}: {reason}"
