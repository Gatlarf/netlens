# Using your privileged-access system (PAM) for logins

*Enterprise edition and the free trial. Settings → Credentials → Add a login → "In your PAM system".*

Netlens needs logins: to open a terminal or a remote desktop, to monitor a host over SSH or WinRM, to install the read-only probe. If your company keeps its privileged
passwords in a vault, Netlens should **ask the vault** instead of holding a copy. That is what this does.

A login of kind **PAM** stores only *where the secret lives* and *how Netlens signs in to the vault*. When something needs the login, Netlens fetches it, uses it, and
drops it.

* [What Netlens does and does not do](#what-netlens-does-and-does-not-do)
* [HashiCorp Vault and OpenBao](#hashicorp-vault-and-openbao)
* [Add the login in Netlens](#add-the-login-in-netlens)
* [Reasons](#reasons)
* [What is logged](#what-is-logged)
* [When the PAM is down](#when-the-pam-is-down)
* [Other PAM systems](#other-pam-systems)
* [Troubleshooting](#troubleshooting)
* [What was tested](#what-was-tested)

## What Netlens does and does not do

| | |
|---|---|
| Stored in Netlens | the vault address, the secret's path, the field names, and **one** bootstrap identity (an AppRole or a token), encrypted like every other secret |
| Fetched | each time the login is used: one terminal or remote session, one probe run, one monitor poll |
| Kept | nowhere. No cache between uses, nothing in the database, nothing in a log, a diagnostic or an AI prompt |
| If the vault says no or cannot be reached | **the use does not happen.** There is no fall-back to a stored password |
| Audit | one line for each check-out (who, which host, which login, why, the vault's request id), never the secret |
| TLS | always verified. A vault with a private CA brings that CA in the login. There is no switch to skip verification |
| Addresses | the same outbound guard as every other address typed into Netlens: no `file:`, no credentials in the address, no link-local or cloud-metadata addresses |

Netlens is not a PAM. It does not rotate, vault or broker passwords. The vault stays the system of record.

## HashiCorp Vault and OpenBao

The KV secrets engine, version 1 and 2. Tested on OpenBao 2.7.2.

**1. Keep the login in a secret.** For example `secret/netlens/linux-admin` with the keys `username` and `password`; or `username`, `private_key` and optionally
`passphrase` for an SSH key. Other key names can be mapped in Netlens.

**2. Give Netlens its own identity that can read only those secrets.** A policy:

```hcl
path "secret/data/netlens/*" { capabilities = ["read"] }       # KV version 2: note the "data/"
# path "kv1/netlens/*"       { capabilities = ["read"] }       # KV version 1
```

**3. Sign in with an AppRole** (preferred; a token also works):

```sh
bao auth enable approle
bao write auth/approle/role/netlens token_policies=netlens-read token_ttl=2m token_max_ttl=5m \
        secret_id_bound_cidrs=<netlens address>/32 token_bound_cidrs=<netlens address>/32
bao read auth/approle/role/netlens/role-id
bao write -f auth/approle/role/netlens/secret-id
```

Why AppRole: the token it gives lives for minutes, is **revoked by Netlens as soon as the secret has been read**, and can be bound to Netlens' address. A fixed
token lasts as long as you made it last; if you use one, give it a short life and a renewal that you control. Use the same commands with `vault` instead of `bao` for
HashiCorp Vault. With namespaces, give the namespace in the login.

The secret id is the one secret that must exist on the Netlens side. Give it the least rights, bind it to the address, and rotate it from your side as you rotate any
other application secret (change it in Netlens: Credentials → Change).

## Add the login in Netlens

Settings → Credentials → **Add a login**, kind *In your PAM system*:

| Field | Meaning |
|---|---|
| PAM system | HashiCorp Vault / OpenBao (KV secrets) |
| Address | `https://vault.example.com:8200` |
| Namespace | only if you use namespaces |
| Secrets engine, Secret path, Version | `secret`, `netlens/linux-admin`, KV version 2 |
| Netlens signs in with | AppRole (role id, secret id) or a token |
| CA certificate | PEM text, only if the vault uses a private CA |
| Field names | only if the secret uses other names than `username`, `password`, `private_key`, `passphrase`, `domain` |
| Ask for a reason every time | see below |

**Try it** (in the list) fetches the login once and says which fields came back, never their values. The login then works everywhere a stored login works: terminal,
remote desktop, host monitors, host probes and host set-up.

Creating and changing PAM logins needs the Enterprise edition (or the trial) and, when step-up is on, a fresh confirmation. If the licence ends, existing PAM logins
keep working: holding a secret in your vault is the safer way, so a lapsing licence never pushes anyone back to stored passwords.

## Reasons

Tick **Ask for a reason every time** and a person must give a ticket number or a few words before the login is used. The reason is written to the audit log and sent
on. A **monitor or any other background job cannot give a reason**, so such a login is refused for them (and is not offered in their lists). Use one login for people
and another for monitoring.

## What is logged

One audit line for each check-out, for example:

```
PAM vault_kv: login "Linux admin" checked out for web01; lease 3b1f…; correlation nl-9c0a41d2e7b3a1f0; purpose: SSH terminal to 10.0.0.12, reason: INC-4711 restart nginx
```

* **lease** is the vault's own request id, **correlation** is sent to the vault in the header `X-Netlens-Correlation`, so the two trails can be joined.
* A refusal is always one line (`REFUSED … (the reason)`), status 403.
* A monitor that polls every minute writes **one line an hour** per login and purpose, not one per poll. Refusals are never thinned out.
* The audit log is forwarded to your SIEM like the rest.

The dashboard's "needs attention" list, Ask, the assistant, MCP and the reports show a PAM login that was refused ("The PAM system did not hand out the login …"). They
never see a secret.

## When the PAM is down

The login is not used: the terminal says why, the monitor reads "the PAM system did not hand out the login: …", the dashboard shows it. When the vault is back, the next
use works; nothing has to be reset. Monitors ask the vault at every poll, so a long outage turns the monitors of those hosts red; that is the intended failure mode.

## Other PAM systems

CyberArk (Central Credential Provider), Delinea Secret Server and BeyondTrust Password Safe, and routing through a bastion, are planned. They use the same framework.
They will be marked *not tested on a real system* until a customer or partner has confirmed them.

## Troubleshooting

| Message | Cause |
|---|---|
| the AppRole sign-in was refused | wrong role id or secret id, or the secret id has expired or been used up, or the address does not match `secret_id_bound_cidrs` |
| this identity may not read that secret | the policy; remember `data/` in the path for KV version 2 |
| there is no secret at that path | engine name, path or version wrong; a deleted secret also gives this |
| the secret does not hold a user name and a password or key | the keys have other names: set them under *Field names* |
| the certificate of the PAM system is not trusted | add the vault's CA certificate to the login |
| cannot reach the PAM system | network, firewall, or the address is blocked by the outbound guard |
| needs a reason … only be used by a person | the login asks for reasons: use it from a terminal or remote session, or use another login for monitoring |

## What was tested

* Against a **real OpenBao 2.7.2**: AppRole and token sign-in, KV version 1 and 2, field mapping, the policy (allowed and refused paths), a wrong secret id, a missing
  secret, and that the AppRole token is revoked after use (checked by asking the server afterwards).
* Against a stand-in server in the automated tests: every refusal, path and address abuse, oversized answers, the reason rules, fail-closed behaviour for the terminal and
  the monitors, audit lines without secrets, the licence rules.
* **Not tested:** HashiCorp Vault Enterprise namespaces on a real server (the header is the documented one), a private CA on a real vault.
