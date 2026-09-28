"""Firefox profile and krb5.conf creation."""

import os

DEFAULT_USERAGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36 Edg/148.0.3967.96"
)

SSO_SPNS = "https://autologon.microsoftazuread-sso.com,https://aadg.windows.net.nsatc.net"


def create_firefox_profile(
    temp_dir: str,
    useragent: str | None = None,
    trusted_uris: str | None = None,
) -> str:
    profile_dir = os.path.join(temp_dir, "profile")
    os.makedirs(profile_dir, exist_ok=True)

    ua = useragent or DEFAULT_USERAGENT
    uris = trusted_uris if trusted_uris is not None else SSO_SPNS
    lines = [
        f'user_pref("network.negotiate-auth.trusted-uris", "{uris}");',
        'user_pref("network.negotiate-auth.using-native-gsslib", true);',
        f'user_pref("general.useragent.override", "{ua}");',
    ]

    user_js_path = os.path.join(profile_dir, "user.js")
    with open(user_js_path, "w") as f:
        f.write("\n".join(lines) + "\n")

    return profile_dir


def _default_sso_hosts() -> list[str]:
    """Negotiation hosts for the Azure SSO SPNs (derived from SSO_SPNS)."""
    return [uri.split("://", 1)[-1] for uri in SSO_SPNS.split(",")]


def create_krb5_conf(
    temp_dir: str, domain: str, sso_hosts: list[str] | None = None
) -> str:
    realm = domain.upper()
    hosts = sso_hosts or _default_sso_hosts()
    domain_realm = "\n".join(f"    {host} = {realm}" for host in hosts)
    content = f"""\
[libdefaults]
    default_realm = {realm}
    dns_lookup_realm = false
    dns_lookup_kdc = false
    rdns = false
    dns_canonicalize_hostname = false

[realms]
    {realm} = {{
        kdc = dummy
    }}

[domain_realm]
{domain_realm}
"""
    conf_path = os.path.join(temp_dir, "krb5.conf")
    with open(conf_path, "w") as f:
        f.write(content)

    return conf_path
