# Day-2 operations

Everything after the install. All of it happens through `Create-New-Cert.ps1` (the creator), run in an
**elevated** PowerShell:

```powershell
& 'C:\Cert\Renewal\Create-New-Cert.ps1'
```

On **Linux**, the same menu, as root:

```bash
sudo pwsh -NoProfile -File /opt/certrenewal/Create-New-Cert.ps1
```

Everything on this page applies to both platforms. Where a path or command differs, the Linux form is
given alongside; [linux.md](linux.md) has the parts that exist only there.

With certificates present it shows an overview of the install (script versions, telemetry, billing, the
managed certificates) and a menu: **[A]dd / [U]pdate / [D]elete / [H]elp / [Q]uit**.

| I want to… | Do this |
|---|---|
| Add a certificate | **[A]dd**. Same prompts as the install, see [README.md](README.md#step-3--add-your-certificates). |
| Change how a certificate is deployed, its service restart, hooks or lead time | **[U]pdate** → pick the certificate. |
| Change the domains or SANs on a certificate | **[D]elete** it, then **[A]dd** it again. |
| Edit the billing block | **[U]pdate** → **[B]**. |
| Remove a certificate | **[D]elete**. Deleting the last one offers to remove the task and config too. |
| See status without changing anything | `Create-New-Cert.ps1 -CheckOnly`, or `Renew-Cert.ps1 -DryRun`. |
| Open this guide from the server | **[H]elp** opens it in the browser. |
| Renew everything right now | `Renew-Cert.ps1 -Force` (read [Force a renewal](#force-a-renewal-now) first). |

---

## Update a certificate

**[U]pdate** first asks what to change: a managed certificate or the billing block. For a certificate it
changes how it is deployed (CertStore → IIS, moved between Netsh / IIS Web / IIS FTP), the post-renewal
service restart, the pre/post-renewal hooks, the App Proxy target, or the renewal lead time.

Each setting that already has a value is offered as **[K]eep (press Enter) / [C]hange / [R]emove**, so
editing one setting never wipes the others. Only **[R]emove** clears a value.

Update **re-binds the existing certificate** in place. It does **not** re-issue, because the domains are
unchanged, and it leaves the old binding alone.

## Billing

The customer identifiers stamped on Teams cards and telemetry. Captured once by bootstrap and afterwards
edited via **[U]pdate → [B]**; each field keeps its current value on Enter. **Abbreviation and invoice
code are required**, everything else is optional.

## Renewal lead time

By default a certificate renews when it has **30 days or less** to expiry. Set a different per-certificate
value at the **[A]dd** or **[U]pdate** prompt, or put a `RenewalThresholdDays` number on the certificate's
entry in `cert-config.json` (picked up on the next daily run). Avoid values at or above about 90 days: the
certificate would renew on every run and hit Let's Encrypt's rate limits.

## Force a renewal now

```powershell
& 'C:\Cert\Renewal\Renew-Cert.ps1' -Force            # renews EVERY managed cert immediately
& 'C:\Cert\Renewal\Renew-Cert.ps1' -Force -DryRun    # shows what would renew, including hooks
```

On **Linux**:

```bash
sudo pwsh -NoProfile -File /opt/certrenewal/Renew-Cert.ps1 -Force
sudo pwsh -NoProfile -File /opt/certrenewal/Renew-Cert.ps1 -Force -DryRun
```

Or let the timer's own unit do it, which is closer to what happens at 03:00:

```bash
sudo systemctl start certrenewal.service && journalctl -u certrenewal.service -n 40
```

`-Force` ignores the lead time and Let's Encrypt's renewal window and re-issues a genuinely new
certificate for every managed name. Use it for an on-demand rotation, for example after a key compromise,
or to exercise a freshly configured hook. **Do not loop it**: repeated forced re-issues hit the
duplicate-certificate rate limit (5 per week per exact domain set).

## Pre- and post-renewal hooks

Point a certificate at your own `.ps1` to run **before** issuance (`PreRenewalScript`) and/or **after** a
successful renew and deploy (`PostRenewalScript`). Set them at the **[A]dd** or **[U]pdate** prompts, or
by hand on the certificate's entry in `cert-config.json`.

The daily renewal runs the hook, so:

- It runs **as SYSTEM**. ⚠️ Keep the `.ps1` somewhere **only administrators can write**, such as under
  `C:\Cert\Renewal\` or `%ProgramFiles%`. A hook on a path standard users can modify is a
  privilege-escalation hole: SYSTEM executes whatever it contains.
- It is **best-effort**. A missing file, a non-`.ps1`, a thrown error or a non-zero exit is logged
  (WARNING plus event `1031`) and **never fails the renewal**. A failing *pre* hook still proceeds to renew.
  A failed hook or service restart on a certificate that did renew raises a warning Teams card
  (*Certificate Renewed - Post-Renewal Action Failed*) so you are told.
- It gets its context from environment variables: `CERTRENEWAL_HOOK_PHASE` (`Pre` or `Post`),
  `CERTRENEWAL_HOOK_DOMAIN`, `CERTRENEWAL_HOOK_TYPE`, `CERTRENEWAL_HOOK_THUMBPRINT`,
  `CERTRENEWAL_HOOK_NOTAFTER`. An existing script needs no special parameters.
- On `-DryRun` the renewal logs `WOULD run …` and does not execute it.

## Export the certificate as files for a service (Windows)

nginx, HAProxy, Tomcat, MongoDB and similar want `cert.pem` / `chain.pem` / `fullchain.pem` /
`privkey.pem` (or one `cert.pfx`) on disk instead of the certificate store. The creator does this for
any deployment type: at **[A]dd**, after the deployment type, answer **y** to *Also export certificate
files for a service?*, pick the format (PEM, PFX or both), the directory (default
`C:\Cert\Renewal\live\<domain>`) and the accounts that may read the files — the service's own account,
such as `NT SERVICE\nginx` or `CORP\svc-tomcat`; press Enter for administrators only. **[U]pdate** adds,
changes or removes the export on an existing certificate and writes the files at once; **[D]elete**
offers to remove them.

What the renewal then does, every night the certificate renews: writes the files, locks the directory
to Administrators + SYSTEM plus the accounts you named (nothing inherited, reapplied on every run, so a
directory somebody loosened by hand is tightened again), and tells your hook where they are in
`CERTRENEWAL_HOOK_CERTDIR`. Use `RestartService` or a post-renewal hook to make the service reload. If
the export fails you get a warning Teams card (*Certificate Renewed - Post-Renewal Action Failed*) and
event `1049`; the certificate itself is still renewed and bound.

The private key is written as Posh-ACME produces it (`BEGIN RSA PRIVATE KEY` / `BEGIN EC PRIVATE KEY`),
the PFX with Posh-ACME's password (`poshacme` unless you changed it). A consumer that insists on PKCS#8
needs `openssl pkcs8 -topk8 -nocrypt` in a post-renewal hook.

### Manual alternative: a post-renewal hook that exports PEM files

The built-in export above is the normal way. The recipe below is for a box that cannot take the current
release yet, or for a layout the export does not produce. A post-renewal hook copies Posh-ACME's files
where the service reads them and locks the directory down. The hook runs inside the renewal, so
Posh-ACME is loaded and the account is selected. Save this as `C:\Cert\Renewal\hooks\Export-Pem.ps1`
(administrators-only path) and set it as the certificate's `PostRenewalScript`:

```powershell
$dir = 'C:\certs\' + $env:CERTRENEWAL_HOOK_DOMAIN          # where the service reads from
$pa  = Get-PACertificate -MainDomain $env:CERTRENEWAL_HOOK_DOMAIN
if (-not $pa) { throw "Posh-ACME has no certificate for $env:CERTRENEWAL_HOOK_DOMAIN" }
New-Item -ItemType Directory -Path $dir -Force | Out-Null
# Administrators + SYSTEM full control, the service account read-only, nothing inherited.
icacls $dir /inheritance:r /grant:r 'BUILTIN\Administrators:(OI)(CI)F' 'NT AUTHORITY\SYSTEM:(OI)(CI)F' 'NT SERVICE\nginx:(OI)(CI)RX' | Out-Null
foreach ($pair in @{ 'cert.pem' = $pa.CertFile; 'chain.pem' = $pa.ChainFile; 'fullchain.pem' = $pa.FullChainFile; 'privkey.pem' = $pa.KeyFile }.GetEnumerator()) {
    Copy-Item -LiteralPath $pair.Value -Destination (Join-Path $dir $pair.Key) -Force
}
Restart-Service nginx   # or whatever reloads the consumer
```

Replace `NT SERVICE\nginx` with the account the service runs as (`CORP\svc-tomcat`, a local user, or
drop that entry when the service runs as SYSTEM or an administrator). The key is a plaintext private key:
the `icacls` line is not optional. Two limits of this recipe: hooks fire only on a **scheduled renewal**,
so the files first appear at the first renewal rather than at issuance (run `Renew-Cert.ps1 -Force` once
if you need them today), and the key is in the format Posh-ACME writes (`BEGIN RSA PRIVATE KEY` or
`BEGIN EC PRIVATE KEY`); a consumer that insists on PKCS#8 needs one more `openssl pkcs8 -topk8 -nocrypt`
step in the hook.

## Entra Application Proxy certificate sync

If a certificate is published through an **Entra Application Proxy** app, the renewal can push each
renewed certificate straight into Entra, so App Proxy never serves a stale certificate. No portal
re-upload, no separate scheduled task.

One-time setup per server. Run it signed in as a **Global Administrator** or **Privileged Role
Administrator**: the consent step assigns Microsoft Graph application roles to the shared app, which
Application Administrator / Cloud Application Administrator cannot grant. The setup checks that one of
those roles is *active* right after sign-in and stops before creating anything if not. If you activate the
role through PIM, do it *before* the sign-in prompt (a token issued earlier does not carry it).

If the consent step is still refused (the setup retries it for about 90 seconds first, because a brand-new
service principal can take a moment to replicate), grant it by hand and rerun: Entra admin center →
**Enterprise applications** → `AppProxy-Certificate-Updater` → **Permissions** → **Grant admin consent**,
then run `Setup-AppProxy.ps1` again. The rerun reuses the app, the service principal and the certificate it
already created and finds the roles granted.

```powershell
# Fresh setup: registers the shared Entra app, mints a per-machine auth cert, writes the AppProxyAuth block
& 'C:\Cert\Renewal\Setup-AppProxy.ps1'

# Already running the standalone AdHoc App Proxy tool? Adopt it instead: reuses its app + cert, maps its
# proxies onto your managed certs, removes its 3:30 AM task, archives its files
& 'C:\Cert\Renewal\Setup-AppProxy.ps1' -Migrate      # add -DryRun first to see the plan
```

On **Linux** it is the same tool and the same one-time setup, with three differences:

```sh
sudo pwsh /opt/certrenewal/Setup-AppProxy.ps1        # add -DryRun first to see the plan
```

- **Sign-in uses a device code.** A server has no browser, so the tool prints a code and a URL to
  complete on your own workstation. **Have the browser ready: the code is valid for two minutes**, and
  the sign-in gives up after that (run the tool again for a fresh code). Run it from a real terminal —
  over SSH use `ssh -t` — because a piped or scripted session cannot show you the code, and the tool
  refuses rather than hanging.
- **The auth credential is a file, not a certificate store entry**:
  `/etc/certrenewal/keys/appproxy-auth.pem`, `0600 root:root`, holding the certificate and its private
  key. The config then carries `AppProxyAuth.AuthCertPath` instead of `AuthCertThumbprint` — the two are
  mutually exclusive, and running the tool rewrites the block with the one this platform reads. Back it
  up as you would any other credential; if it is lost, re-run the tool and a new one is minted and
  registered (the old public key stays on the app, harmlessly, until it expires).
- **`-Migrate` is refused**, because the AdHoc tool it adopts only ever existed on Windows.

The per-server auth credential is per server on both platforms: each box mints its own and appends its
own public key to the one shared Entra app, so a Linux box that publishes through App Proxy has to run
this locally.

Then, per certificate, choose the App Proxy app at the creator's **[A]dd** or **[U]pdate** prompt
(*Sync this certificate to an Entra Application Proxy app?*). From then on the daily renewal pushes the
new certificate after a renewal **and** reconciles drift on every run, so a missed push heals itself. It
also renews its own auth credential before expiry, on both platforms: within 30 days of expiry it mints
a replacement, registers it alongside the current one and switches to it on the **next** run, so the
overlap covers Entra's replication. On Linux the new credential is written **beside** the old one as
`/etc/certrenewal/keys/appproxy-auth-<yyyyMMdd>.pem` and the old file is kept — it is the rollback, and
it is the only on-disk trace that a rotation happened. A successful push raises a Teams card; a failure
raises a warning card and never blocks the renewal. If App Proxy is not set up on a box, the prompt is
simply skipped.

## Operator accountability

The creator's Add / Update / Delete / Billing actions, and bootstrap, ask once per session for **your work
email**. It is recorded on the telemetry rows so a change is attributable even when the logged-in account
is a shared admin account. The OS identity is recorded as well. The daily renewal has no operator, and a
non-interactive bootstrap skips the prompt.

## Config backups

Before every change the creator and the daily renewal write a snapshot of the previous `cert-config.json`
to `C:\Cert\Renewal\config-backups\cert-config.<timestamp>.<reason>.json`. The newest 20 are kept. Use
them to see exactly what a save changed, or restore one by copying it back over `cert-config.json`.

## Decommissioning a server or offboarding a customer

**You do not need to do anything on the server.** A server that is switched off or deleted simply stops
reporting, and the cert team's fleet view ages it out on its own: flagged **stale** after two days
without a report, **retired** (hidden) after 14. If a customer's servers all go quiet together, that is
flagged once for the customer as a whole. A server that comes back is shown again automatically.

Only if you are removing cert-renewal from a server that **keeps running**:

1. Run the creator and **[D]elete** every certificate. Deleting the last one also removes the daily run
   (the scheduled task on Windows, `certrenewal.timer` on Linux) and offers to remove the renewal script
   and its config.
2. Decide separately what happens to the deployed certificate files; a service may still be using them.

A replacement server is set up like any new one, and its first certificate `[A]dd` re-issues the names
the old one held. Nothing renews a terminated server's certificates, and nothing revokes them: they
expire on their own date.

## Things that happen without you

- **Secret rotation.** If the cert team rotates the Domeneshop token or Teams webhook in Key Vault, the
  daily run picks up the new value.
- **Script updates.** The renewal and the creator check the published manifest each run and replace
  themselves in place after verifying the signature. Run `Create-New-Cert.ps1` to force a check now; if the
  creator updates *itself* it stops and asks you to run it again.
- **Self-healing.** A certificate misconfigured as Netsh that is really IIS-owned is reclassified on its
  next daily run. A missed App Proxy push is retried on the next run.

## Where things live

| What | Where |
|---|---|
| Scripts and config | `C:\Cert\Renewal\` (`Renew-Cert.ps1`, `Create-New-Cert.ps1`, `Setup-AppProxy.ps1`, `cert-config.json`, `cert-secrets.json`) |
| Per-run logs (90 days) | `C:\Cert\Renewal\log\` |
| Event log | Windows Event Log → *Application* → source **CertRenewal** |
| Config snapshots | `C:\Cert\Renewal\config-backups\` |
| Shared ACME account and order state | `C:\ProgramData\Posh-ACME\` |

On **Linux**:

| What | Where |
|---|---|
| Scripts | `/opt/certrenewal/` |
| Config and secrets | `/etc/certrenewal/` (`cert-config.json`, `cert-secrets.json`, `keys/`) |
| Per-run logs (90 days) | `/var/log/certrenewal/` |
| Event log | journald — `journalctl -t CertRenewal`, or by event id: `journalctl CERTRENEWAL_EID=1020` (renewal succeeded) |
| Config snapshots | `/var/lib/certrenewal/config-backups/` |
| Shared ACME account and order state | `/var/lib/certrenewal/posh-acme/` |
| Deployed certificates | `/var/lib/certrenewal/live/<domain>/` (or wherever `Files.Directory` points) |

Something not working? See [troubleshooting.md](troubleshooting.md).
