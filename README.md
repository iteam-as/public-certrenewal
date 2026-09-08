> **CI-managed artifact mirror - do not edit by hand.** Every file in this repository is generated and published from the private source repo on each tagged release; a manual change is overwritten by the next release. Report problems to the cert team.

# Cert-Renewal — Operations Guide

Cert-renewal keeps Let's Encrypt certificates on a Windows server valid, automatically. You set it up
**once** with `bootstrap.ps1`, add your certificates with `Create-New-Cert.ps1`, and from then on a daily
task renews every certificate that is close to expiry and re-binds it wherever it is used (IIS sites, FTP,
or HTTP.SYS/netsh). The scripts also keep themselves up to date.

## Pick your path

| I want to… | Go to |
|---|---|
| **Set up a new server** | This page — start at [Quick start](#quick-start-fresh-server). |
| **Upgrade a server that runs the old v1 setup** | [upgrade-from-v1.md](upgrade-from-v1.md) |
| Add, change or remove a certificate; force a renewal; hooks; App Proxy | [day-2-operations.md](day-2-operations.md) |
| Something went wrong | [troubleshooting.md](troubleshooting.md) |

---

## Quick start (fresh server)

Three commands in an **elevated** PowerShell. You need `telemetry-client.pfx` and its password from the
cert team (see [Before you start](#before-you-start)).

```powershell
# 1. Download the current signed bootstrap
$mirror = 'https://raw.githubusercontent.com/iteam-as/public-certrenewal/main'
Invoke-WebRequest "$mirror/bootstrap.ps1" -OutFile "$env:TEMP\bootstrap.ps1" -UseBasicParsing

# 2. Run it once (it asks for your work email and the customer's billing identifiers)
$pwd = Read-Host 'PFX password' -AsSecureString
& "$env:TEMP\bootstrap.ps1" -TelemetryCertPfxPath 'C:\path\telemetry-client.pfx' -TelemetryCertPassword $pwd

# 3. Add your certificates
& 'C:\Cert\Renewal\Create-New-Cert.ps1'
```

The rest of this page explains what you need beforehand, what each step does, and **what success looks
like** so you can tell it worked.

---

## Before you start

Tick these off before you begin. Each one is something bootstrap or the creator will stop on if it is
missing.

- [ ] **Administrator rights** on the server (an elevated PowerShell / RDP session).
- [ ] **PowerShell 5.1 or later.** Built into Windows Server; nothing to install.
- [ ] **Outbound HTTPS** from the server to:
  - `raw.githubusercontent.com` (the scripts),
  - `login.microsoftonline.com`, `*.vault.azure.net`, `*.ingest.monitor.azure.com` (secrets and telemetry),
  - Let's Encrypt and Domeneshop (certificate issuance).

  No inbound access is needed.
- [ ] **`telemetry-client.pfx` and its password**, supplied by the cert team. This is how the server reads
  the shared secrets (Domeneshop DNS token, Teams webhook, contact email) from Azure Key Vault. You need it
  the **first time only**: bootstrap imports it into the machine certificate store and then deletes the file.
- [ ] **The customer's billing identifiers**: abbreviation and invoice code are required; customer name,
  number and services are optional. Bootstrap asks for them; they are stamped on alerts and reporting.
- [ ] **A DNS record per certificate name.** Validation uses DNS-01 with a CNAME delegation:
  `_acme-challenge.<your-fqdn>` must be a CNAME pointing into the `certval.no` zone. Get this in place with
  whoever manages the domain's DNS before you add the certificate. If it is missing, the creator pauses and
  prints the exact record to create.

> You never type a secret. The Domeneshop token, Teams webhook and contact email all come from Azure Key
> Vault automatically.

### The scripts

| Script | You run it | When |
|---|---|---|
| `bootstrap.ps1` | **Yes — once per server**, elevated | First-time setup, or a v1 → v2 upgrade |
| `Create-New-Cert.ps1` | **Yes — interactively**, elevated | To add, update or remove certificates |
| `Setup-AppProxy.ps1` | **Only if you use Entra Application Proxy** — once per server, elevated | To enable App Proxy certificate sync |
| `Renew-Cert.ps1` | **No** — runs automatically as a daily task | Every day at 03:00, as SYSTEM |

---

## Step 1 — Download bootstrap

```powershell
$mirror = 'https://raw.githubusercontent.com/iteam-as/public-certrenewal/main'
Invoke-WebRequest "$mirror/bootstrap.ps1" -OutFile "$env:TEMP\bootstrap.ps1" -UseBasicParsing
```

Bootstrap does not update itself, so always fetch a fresh copy when you use it.

✅ **Success looks like:** `Test-Path "$env:TEMP\bootstrap.ps1"` returns `True`.

---

## Step 2 — Run bootstrap (once, elevated)

Place `telemetry-client.pfx` somewhere on the server, then:

```powershell
$pwd = Read-Host 'PFX password' -AsSecureString
& "$env:TEMP\bootstrap.ps1" -TelemetryCertPfxPath 'C:\path\telemetry-client.pfx' -TelemetryCertPassword $pwd
```

> **Tip:** add `-DryRun` first. It logs everything bootstrap *would* do and changes nothing.

**It asks you for two things:**

1. **Your work email.** Recorded on the telemetry rows so a change is attributable even when the logged-in
   account is a shared admin account.
2. **The billing block**: customer abbreviation, name, number, invoice code, services.

To run **unattended** (no prompts), pass the billing values on the command line:

```powershell
& "$env:TEMP\bootstrap.ps1" -TelemetryCertPfxPath '…\telemetry-client.pfx' -TelemetryCertPassword $pwd `
    -Abr DMO -CustomerName 'Demo Firma' -CustomerNr DMO001 -InvoiceCode DMO_001 -Services Web
```

**What it does**, all automatic and safe to re-run:

1. Installs the code-signing trust so the signed scripts are accepted.
2. Imports the Key Vault certificate (non-exportable) and **deletes the PFX from disk**.
3. Installs the required PowerShell modules (Az.Accounts, Az.KeyVault, Posh-ACME, DnsClient-PS)
   machine-wide.
4. Downloads the signed `Renew-Cert.ps1`, `Create-New-Cert.ps1` and `Setup-AppProxy.ps1` into
   `C:\Cert\Renewal\`, verifying the hash and signature of each.
5. Writes `cert-config.json` (billing block, no certificates yet) and pulls the shared secrets from Key Vault.
6. Registers the daily **Renew-Cert** scheduled task (03:00, runs as SYSTEM).

✅ **Success looks like:**

- You see `=== bootstrap finished ===` with no red `FATAL:` line above it, followed by a **Next steps** block
  that lists what to do now and offers to open this guide in your browser.
- `C:\Cert\Renewal\` contains `Renew-Cert.ps1`, `Create-New-Cert.ps1`, `cert-config.json` and
  `cert-secrets.json`.
- `Get-ScheduledTask -TaskName 'Renew-Cert'` shows the task with state **Ready**.
- The PFX file you pointed at is gone.

Yellow `WARNING` lines are not failures. A warning about the vault sync or a module install means the box
is set up but one best-effort step did not finish; the next creator run and the daily renewal heal it.

❌ **If it stops** with a red line, find the message in [troubleshooting.md](troubleshooting.md), fix the
cause, and run the same command again.

---

## Step 3 — Add your certificates

```powershell
& 'C:\Cert\Renewal\Create-New-Cert.ps1'
```

On a fresh box the creator goes straight into the **Add** flow. For each certificate it asks, in order:

1. **Primary FQDN**, for example `app.example.no`, or `*.example.no` for a wildcard.
2. **SANs?** Additional names on the same certificate (optional).
3. **Deployment type**, that is, how the renewed certificate gets applied:
   - **[W] IIS Web** rebinds the HTTPS bindings of your IIS site(s). *Use this for normal IIS sites.*
   - **[F] IIS FTP** rebinds an IIS FTP site (asks for the site name).
   - **[N] Netsh HTTP.SYS** is for services bound directly with `netsh http`, not IIS.
   - **[C] CertStore only** installs the certificate and changes no bindings.

   > If unsure for a website, choose **[W] IIS Web**. If you pick **[N] Netsh** for a binding that turns
   > out to be IIS-owned, the creator warns and offers to switch you to **[W] IIS Web**. Accept it.
4. **Restart a service after renewal?** Optional. Name a Windows service to restart after each renewal.
5. **Run a custom script before / after renewal?** Optional pre/post-renewal hooks. See
   [day-2-operations.md](day-2-operations.md#pre--and-post-renewal-hooks) for the rules.
6. **Sync to an Entra Application Proxy app?** Only shown when `Setup-AppProxy.ps1` has been run on this box.
7. **Renew how many days before expiry?** Press Enter for the default **30**.

Then it validates DNS for each name: the `_acme-challenge` CNAME and the CAA record. If something is
missing it prints exactly what is needed and offers **[R]etry / [S]kip / [A]bort**. Fix the DNS, then
**[R]etry**. Once validation passes it issues the certificate from Let's Encrypt, installs it, applies the
bindings, and registers or refreshes the daily task.

Press Enter on an empty FQDN when you are done adding.

✅ **Success looks like:** a green `Certificate issued: subject=... thumbprint=... expires=...` line, then
`Deployment completed for <fqdn>.`, and finally `Add flow complete: N certificate(s) issued and deployed.`
The certificate is listed under *Managed certificates* the next time you start the creator.

❌ **DNS validation keeps failing?** See the DNS rows in [troubleshooting.md](troubleshooting.md).

---

## Step 4 — Verify

```powershell
& 'C:\Cert\Renewal\Create-New-Cert.ps1' -CheckOnly   # lists managed certs + script versions
Get-ScheduledTask -TaskName 'Renew-Cert'             # should exist, state Ready
& 'C:\Cert\Renewal\Renew-Cert.ps1' -DryRun           # shows what the daily run would do, changes nothing
```

✅ **Success looks like:** `-CheckOnly` lists every certificate you added with an expiry date, and the
`-DryRun` renewal ends with a green `=== Renew-Cert finished (outcome=...) ===` line and no red lines.

That is it. The server now renews and re-binds on its own.

---

## What happens from now on

- **Every day at 03:00** the renewal task checks each managed certificate and renews any with 30 days or
  less to expiry (per-certificate lead time is configurable). A renewal sends a Teams card.
- **The scripts update themselves.** The renewal and the creator check the published manifest each run and
  replace themselves in place after verifying the signature. If the creator updates *itself* it stops and
  asks you to run it again.
- **Secret rotation is automatic.** If the cert team rotates the Domeneshop token or Teams webhook in Key
  Vault, the daily run picks up the new value. You do nothing.
- **Logs** are in `C:\Cert\Renewal\log\` (per-run transcripts, 90 days) and in Windows Event Log →
  *Application* → source **CertRenewal**.

For everything after install, see [day-2-operations.md](day-2-operations.md).

---

## About this repository

This is the **published artifact mirror** for cert-renewal. Every file here is generated and pushed by CI
from the private source repository on each tagged release; nothing is edited by hand. The servers download
the scripts from here over HTTPS.

| File | Purpose |
|---|---|
| `manifest.json` | Current version, SHA-256 and download URL of each script. |
| `bootstrap.ps1` | One-shot per-server setup and v1 → v2 upgrade (signed). |
| `Create-New-Cert.ps1` | Interactive certificate creator / admin tool (signed). |
| `Renew-Cert.ps1` | Daily renewal, self-update and heartbeat (signed). |
| `Setup-AppProxy.ps1` | Optional one-time Entra Application Proxy setup (signed). |
| `codesign.cer` | Public code-signing certificate the servers trust. |

Every script is Authenticode-signed and SHA-256-pinned in the manifest. A server verifies both before it
runs or replaces a script. Questions and problems go to the cert team, who work in the source repository.
