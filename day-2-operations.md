# Day-2 operations

Everything after the install. All of it happens through `Create-New-Cert.ps1` (the creator), run in an
**elevated** PowerShell:

```powershell
& 'C:\Cert\Renewal\Create-New-Cert.ps1'
```

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

## Entra Application Proxy certificate sync

If a certificate is published through an **Entra Application Proxy** app, the renewal can push each
renewed certificate straight into Entra, so App Proxy never serves a stale certificate. No portal
re-upload, no separate scheduled task.

One-time setup per server, by a Graph administrator:

```powershell
# Fresh setup: registers the shared Entra app, mints a per-machine auth cert, writes the AppProxyAuth block
& 'C:\Cert\Renewal\Setup-AppProxy.ps1'

# Already running the standalone AdHoc App Proxy tool? Adopt it instead: reuses its app + cert, maps its
# proxies onto your managed certs, removes its 3:30 AM task, archives its files
& 'C:\Cert\Renewal\Setup-AppProxy.ps1' -Migrate      # add -DryRun first to see the plan
```

Then, per certificate, choose the App Proxy app at the creator's **[A]dd** or **[U]pdate** prompt
(*Sync this certificate to an Entra Application Proxy app?*). From then on the daily renewal pushes the
new certificate after a renewal **and** reconciles drift on every run, so a missed push heals itself. It
also renews its own auth certificate before expiry. A successful push raises a Teams card; a failure
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

Something not working? See [troubleshooting.md](troubleshooting.md).
