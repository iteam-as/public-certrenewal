# Upgrade a v1 server to v2

A **v1 server** already has `C:\Cert\Renewal\cert-config.json` from the old setup. You can tell it is v1
because the file has no `SchemaVersion` field. The upgrade keeps your **existing domains and ACME
account**, so no certificate is re-issued. Bootstrap migrates the configuration in place.

Start at [README.md](README.md#before-you-start) for the prerequisites. You need the same
`telemetry-client.pfx` and password as a fresh install.

## Quick start

```powershell
# 1. Download the current signed bootstrap
$mirror = 'https://raw.githubusercontent.com/iteam-as/public-certrenewal/main'
Invoke-WebRequest "$mirror/bootstrap.ps1" -OutFile "$env:TEMP\bootstrap.ps1" -UseBasicParsing

# 2. Dry-run first: shows the migration it would apply, changes nothing
$pwd = Read-Host 'PFX password' -AsSecureString
& "$env:TEMP\bootstrap.ps1" -TelemetryCertPfxPath 'C:\path\telemetry-client.pfx' -TelemetryCertPassword $pwd -DryRun

# 3. Same command without -DryRun to migrate
& "$env:TEMP\bootstrap.ps1" -TelemetryCertPfxPath 'C:\path\telemetry-client.pfx' -TelemetryCertPassword $pwd
```

Then remove the old v1 creator script (Step 5 below). That step is manual and easy to forget.

---

## Step 1 — Download bootstrap

```powershell
$mirror = 'https://raw.githubusercontent.com/iteam-as/public-certrenewal/main'
Invoke-WebRequest "$mirror/bootstrap.ps1" -OutFile "$env:TEMP\bootstrap.ps1" -UseBasicParsing
```

✅ **Success looks like:** `Test-Path "$env:TEMP\bootstrap.ps1"` returns `True`.

## Step 2 — Dry-run the migration

```powershell
$pwd = Read-Host 'PFX password' -AsSecureString
& "$env:TEMP\bootstrap.ps1" -TelemetryCertPfxPath 'C:\path\telemetry-client.pfx' -TelemetryCertPassword $pwd -DryRun
```

On a v1 box this reports the exact migration it *would* apply: how many domains carry over, the Posh-ACME
account, and that it would drop the old in-config Teams webhook (now a Key Vault secret). Nothing changes.

✅ **Success looks like:** a `[DryRun] WOULD back up cert-config.json ... and migrate to v2 (carry N
domain(s) ...)` line where N matches the number of certificates the server manages today.

❌ **N is wrong or a domain is missing?** Stop here and contact the cert team before migrating.

## Step 3 — Run the migration

Re-run the same command **without** `-DryRun`. Bootstrap detects the v1 config and:

- Backs up `cert-config.json` to `cert-config.json.pre-2.0.bak`.
- Carries over your **domains**, the **Posh-ACME account** and `SharedPoshAcmePath` into the v2 config,
  and adds the `Telemetry` block and version stamps.
- **Asks for the billing block** (v1 had none). Abbreviation and invoice code are required. For an
  unattended run pass `-Abr`, `-InvoiceCode` and optionally `-CustomerName`, `-CustomerNr`, `-Services`.
- Replaces the old generated `Renew-Cert.ps1` with the signed v2 script. The old script is **not** backed
  up because it held the shared secrets in clear text.
- Does everything a fresh install does: signing trust, Key Vault certificate, modules, signed scripts,
  secrets from the vault, the daily task.

✅ **Success looks like:** a green `Migrated config to v2: carried N domain(s) ...` line, then
`=== bootstrap finished ===` with no red `FATAL:` line, followed by a **Next steps** block with the verify
commands from Step 4.

## Step 4 — Verify

```powershell
& 'C:\Cert\Renewal\Create-New-Cert.ps1' -CheckOnly   # your domains should all be listed
& 'C:\Cert\Renewal\Renew-Cert.ps1' -DryRun           # the dry-run sees the migrated config cleanly
Get-ScheduledTask -TaskName 'Renew-Cert'             # exists, state Ready
```

✅ **Success looks like:** every domain from the v1 config appears in `-CheckOnly`, and the `-DryRun`
renewal finishes without red lines. Your certificates keep renewing on their normal schedule; nothing is
re-issued.

Delete `cert-config.json.pre-2.0.bak` once you have confirmed everything is healthy.

## Step 5 — Remove the old v1 creator

The v1 setup script, `Create-New-Cert-SharedConfig.ps1`, usually lives **outside** `C:\Cert\Renewal\`,
often one level up in `C:\Cert\`. The migration does **not** touch it, because its path was chosen by
whoever installed v1 and bootstrap cannot find it reliably.

**Archive or delete it now.** If someone runs it again out of habit it will regenerate a v1-style
`Renew-Cert.ps1` with the shared secrets baked in *and* rewrite the config, undoing the migration.

From now on the only creator is `C:\Cert\Renewal\Create-New-Cert.ps1`. See
[day-2-operations.md](day-2-operations.md) for how to use it.

---

## If something went wrong

Bootstrap is safe to re-run. Fix the cause listed in [troubleshooting.md](troubleshooting.md), then run
the same command again. To roll back the configuration, copy `cert-config.json.pre-2.0.bak` back over
`cert-config.json` and contact the cert team.
