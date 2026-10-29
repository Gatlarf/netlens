# Using your privileged-access system (PAM) for logins

*Enterprise edition and the free trial. Settings → Credentials → Add a login → "In your PAM system".*

Netlens needs logins: to open a terminal or a remote desktop, to monitor a host over SSH or WinRM, to install the read-only probe. If your company keeps its privileged
passwords in a vault, Netlens should **ask the vault** instead of holding a copy. That is what this does.

A login of kind **PAM** stores only *where the secret lives* and *how Netlens signs in to the vault*. When something needs the login, Netlens fetches it, uses it, and
drops it.

* [What Netlens does and does not do](#what-netlens-does-and-does-not-do)
* [HashiCorp Vault and OpenBao](#hashicorp-vault-and-openbao)
* [Add the login in Netlens](#add-the-login-in-netlens)
* [CyberArk](#cyberark)
* [Delinea Secret Server](#delinea-secret-server)
* [BeyondTrust Password Safe](#beyondtrust-password-safe)
* [Routing through a bastion or a session proxy](#routing-through-a-bastion-or-a-session-proxy)
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

## CyberArk

The **Central Credential Provider (CCP)** web service (`/AIMWebService/api/Accounts`). **Not tested on a real CyberArk yet:** it follows CyberArk's documentation and is tested
against a stand-in server that does the same. Try it on a test account first, and tell us what you find.

**In CyberArk:**
1. Create an **application** (for example `Netlens`) under Applications. Under *Authentication* add a **client certificate** (serial number, issuer or DN) and the **allowed
   address** of Netlens. A certificate is strongly recommended; an application id alone is only as safe as the network.
2. Add the application as a member of the **safe** that holds the monitoring and access accounts with the permission **Retrieve accounts** and nothing else.
3. If the account needs dual control or exclusive use, a monitor cannot get it (nobody is there to approve); use a separate account for monitoring.

**In Netlens** (Settings → Credentials → *In your PAM system* → CyberArk): the address of the CCP web service (`https://cyberark.example.com`), the application id, the safe,
the account **object name** (or its user name and address), whether the secret is a password or an SSH private key, the client certificate and its key, and the CA
certificate if your CyberArk uses a private CA. The client key is stored encrypted like every other secret and is never shown again.

Netlens sends the application id, safe, folder and object, `FailRequestOnPasswordChange=true` (a password that is being changed is refused, not handed out half-way), and a
**reason** that names Netlens, the person, the purpose and the correlation id, so the CyberArk audit shows who the password was really for. The client certificate is
loaded from a private temporary file in memory (`/dev/shm`) that is removed straight away.

## Delinea Secret Server

On premises or Secret Server Cloud. **Not tested on a real Secret Server yet:** written from Delinea's REST documentation and tested against a stand-in. The details most
likely to differ on a real server (how a secret that requires check-out or a comment is read) are the first thing to check on a test secret.

**In Secret Server:** make a user for Netlens (a long random password, no interactive use, allowed from Netlens' address), give it **View** on the folder that holds the
monitoring and access accounts and nothing else. Note the **secret id** (the number in `…/secrets/1234`).

**In Netlens:** the address, the secret id, the application user and its password (and its domain, if any). Netlens signs in with the OAuth2 password grant, reads the
secret, takes `username` and `password` (or `private-key`) from its fields, sends a comment that names Netlens, the person, the purpose and the correlation id, and, if
Secret Server checked the secret out for it, **checks it in again 90 seconds later** (when the login attempt is over; checking in at once could start a password change
while the login is still under way).

## BeyondTrust Password Safe

**Not tested on a real Password Safe yet:** written from BeyondTrust's API guide (v3) and tested against a stand-in. Most likely to differ: the check-in call, how a request
that needs approval answers, and the sign-in variants.

**In Password Safe:** an **API registration** for Netlens (a key, limited to Netlens' address, with the role that may only request passwords) and a **run-as user**. The
managed account must allow a *view password* request without approval for the Netlens user (an approval cannot be given to a monitor).

**In Netlens:** the address, the API key, the run-as user (and password if it needs one), the managed system name and the managed account name. Per use Netlens signs in,
looks the account up, makes a **five-minute request** for the password with a reason that carries the person, purpose and correlation id, reads it, and **checks the request in
and signs out 90 seconds later**. A conflicting open request is reused.

## Routing through a bastion or a session proxy

Many companies allow SSH to servers only through a **bastion**, or only through a **PAM session proxy** that records the session (CyberArk PSM for SSH, BeyondTrust, Delinea
and others). Any stored login (a password, a key or a PAM login) can carry a **route** (Settings → Credentials → *Reach the host*). It applies to the web terminal and to
SSH monitors and remediation. Remote desktop connects directly.

| Kind | What Netlens does |
|---|---|
| **Jump host (bastion)** | signs in to the bastion with a stored login of your choice (which can live in your PAM), opens a channel to the host through it, and signs in to the host there. **The host's own key is still checked**: a bastion cannot swap the machine behind it unnoticed. |
| **PAM session proxy** | connects to the proxy only, with a user name that names the target, made from a template: `{user}@{target}`, `{user}@account@{target}`, with `{user}`, `{target}` and `{port}` available. The proxy opens and records the session to the host. |

**Pin the host key of the bastion or proxy** (`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` gives `SHA256:…`); without a pin the key is trusted when first seen. A route
is checked when it is saved (address, port, template characters, the bastion login must be one you may use and must not use a route itself) and again when it is used. A user
name or address with a space or control character cannot be put into a proxy user name. The audit line of a terminal session names the bastion or proxy that was used, and the
login for a vaulted bastion is a PAM check-out like any other ("bastion for SSH terminal").

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

A cloud secret manager (Azure Key Vault, AWS Secrets Manager) can be added if asked.

## Troubleshooting

| Message | Cause |
|---|---|
| the AppRole sign-in was refused | wrong role id or secret id, or the secret id has expired or been used up, or the address does not match `secret_id_bound_cidrs` |
| this identity may not read that secret | the policy; remember `data/` in the path for KV version 2 |
| there is no secret at that path | engine name, path or version wrong; a deleted secret also gives this |
| the secret does not hold a user name and a password or key | the keys have other names: set them under *Field names* |
| the certificate of the PAM system is not trusted | add the vault's CA certificate to the login |
| cannot reach the PAM system | network, firewall, or the address is blocked by the outbound guard |
| the PAM system did not accept the connection: it wants a client certificate | CyberArk requires mutual TLS: add the client certificate and key |
| Secret Server refused the application user / BeyondTrust refused the API registration | user, password, key, run-as user, or the allowed address |
| CyberArk refused the application | application id, certificate binding, allowed address or safe permission |
| needs a reason … only be used by a person | the login asks for reasons: use it from a terminal or remote session, or use another login for monitoring |

## What was tested

* Against a **real OpenBao 2.7.2**: AppRole and token sign-in, KV version 1 and 2, field mapping, the policy (allowed and refused paths), a wrong secret id, a missing
  secret, and that the AppRole token is revoked after use (checked by asking the server afterwards).
* Against a stand-in server in the automated tests: every refusal, path and address abuse, oversized answers, the reason rules, fail-closed behaviour for the terminal and
  the monitors, audit lines without secrets, the licence rules.
* **Not tested:** HashiCorp Vault Enterprise namespaces on a real server (the header is the documented one), a private CA on a real vault.
