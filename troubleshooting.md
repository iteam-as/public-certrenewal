# Troubleshooting

## First, look here

Every run writes a transcript and event-log entries. Read those before anything else.

```powershell
Get-ChildItem 'C:\Cert\Renewal\log\' | Sort-Object LastWriteTime -Descending | Select-Object -First 5
Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'CertRenewal' } -MaxEvents 30 |
    Format-Table TimeCreated, Id, LevelDisplayName, Message -AutoSize -Wrap
```

Colours in the console mean:

| Colour | Level | Meaning |
|---|---|---|
| Red | `ERROR` / `FATAL` | Something did not happen. A `FATAL:` line stops the run. |
| Yellow | `WARNING` | A best-effort step did not finish. The run continued; the next run usually heals it. |
| Green | `SUCCESS` | A step completed. |

Everything is safe to re-run. Add `-DryRun` to any script to see what it would do without changing anything.

## Bootstrap

| Symptom | What to do |
|---|---|
| *bootstrap.ps1 must run elevated* | Re-open PowerShell as Administrator. |
| *SP cert … not in LocalMachine\My and no PFX supplied* | Pass `-TelemetryCertPfxPath` and `-TelemetryCertPassword`. You need the PFX on the first run. |
| *Failed to install module …* (yellow) | Confirm outbound HTTPS to `www.powershellgallery.com`, then run bootstrap again. It skips what is already installed. |
| *Vault secrets sync failed* (yellow) | Confirm outbound HTTPS to `login.microsoftonline.com` and `*.vault.azure.net`. The box is set up; the next creator run and the daily renewal retry the sync. |
| Downloaded script rejected (*sha256 mismatch* or *NotSigned*) | Fetch a fresh `bootstrap.ps1` and run it again. If it persists, contact the cert team: the published files may be mid-release. |
| *Scheduled-task registration did not complete* | Look at the error above it. Run bootstrap again once the cause is fixed. |
| Migration count looks wrong in `-DryRun` | Do not migrate. Contact the cert team with the dry-run log. |

## Adding a certificate

| Symptom | What to do |
|---|---|
| Issuance pauses on DNS validation, *CNAME record not found* | Create the `_acme-challenge.<fqdn>` CNAME. The creator prints the exact name and target. Then **[R]etry**. |
| *This server cannot reach the public resolvers* | Outbound DNS (port 53 to 8.8.8.8 / 1.1.1.1) is blocked on the server, so the check ran against internal DNS only. Verify the record from a machine with internet access: `nslookup -type=CNAME _acme-challenge.<fqdn> 8.8.8.8`. If it is there, internal DNS has not picked it up yet. Wait, then **[R]etry**. |
| Issuance pauses on CAA validation | Add a CAA record allowing `letsencrypt.org` (the creator prints the format), then **[R]etry**. |
| *Required module 'DnsClient-PS' is not installed* | Run bootstrap again; it installs the module. |
| Chose Netsh but the creator says the binding is IIS-owned | Accept the offer to switch to **[W] IIS Web**. |
| Let's Encrypt rate limit | Wait. Duplicate-certificate limit is 5 per week per exact domain set. Do not loop `-Force`. |

## Daily renewal

| Symptom | What to do |
|---|---|
| *cert-secrets.json not found* | Run bootstrap again; it pulls the secrets from Key Vault. Confirm outbound HTTPS to Azure. |
| A certificate did not renew, Teams card says *failed* | Read the run log. Common causes: the `_acme-challenge` CNAME was removed, or outbound HTTPS to Let's Encrypt / Domeneshop is blocked. Fix, then `Renew-Cert.ps1 -Force` for that box or wait for the next daily run. |
| *Certificate Renewed - Post-Renewal Action Failed* card | The certificate renewed. The service restart or hook failed. Check the hook path exists, is a `.ps1`, and is writable by administrators only. |
| App Proxy push failed (warning card) | The certificate is renewed locally. The daily run retries the push and reconciles on every run. If it keeps failing, re-run `Setup-AppProxy.ps1`. |
| Scripts do not seem to update | Run `Create-New-Cert.ps1`; it checks the manifest and updates. If it says it updated *itself*, run it again. |
| Log says *manifest signature refused* (event 1040) and the scripts stop updating | The scripts require a valid signature on the update manifest — missing, unreadable or wrong all refuse alike. **Certificates keep renewing normally**; only self-update stops, so this is not urgent out of hours. Tell the cert team and change nothing on the server; never download scripts by hand. The same run also reports a `manifest-unverified` line to the monitoring log, so the cert team usually sees it without being told. |
| On bootstrap: *manifest signature refused* and nothing is installed | Same cause, but during a first install there is nothing to fall back to, so bootstrap stops deliberately rather than placing unverified scripts. Nothing was changed on the server. Tell the cert team; re-run bootstrap once they confirm the manifest is fixed. |

## Before you contact the cert team

Include these and the fix is usually one message:

1. Output of `& 'C:\Cert\Renewal\Create-New-Cert.ps1' -CheckOnly` (versions, managed certificates).
2. The newest file in `C:\Cert\Renewal\log\`.
3. The exact red or yellow line you are asking about.

Back to [README.md](README.md) · [day-2-operations.md](day-2-operations.md) · [upgrade-from-v1.md](upgrade-from-v1.md)
