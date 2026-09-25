# Troubleshooting

## First, look here

Every run writes a transcript and event-log entries. Read those before anything else.

```powershell
Get-ChildItem 'C:\Cert\Renewal\log\' | Sort-Object LastWriteTime -Descending | Select-Object -First 5
Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'CertRenewal' } -MaxEvents 30 |
    Format-Table TimeCreated, Id, LevelDisplayName, Message -AutoSize -Wrap
```

On **Linux** the same two things, in the two places Linux keeps them:

```bash
ls -t /var/log/certrenewal/ | head -5                  # per-run transcripts
journalctl -t CertRenewal -n 30 --no-pager             # everything the scripts logged
journalctl -u certrenewal.service -n 40 --no-pager     # what the nightly unit did
journalctl CERTRENEWAL_EID=1020 --since -7d            # one event id, e.g. every renewal this week
```

The event ids are the same on both platforms, so a dashboard or a runbook keyed on them works either way.

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
| Let's Encrypt rejects the order with a CAA error although the pre-check passed | The CAA record that governs a name can sit **above** it: the check walks up the tree (RFC 8659) and stops at the first zone that answers, which for a host that is a CNAME (Application Proxy, a CDN, a load balancer) is usually the zone apex. Add `CAA 0 issue "letsencrypt.org"` there — plus `CAA 0 issuewild "letsencrypt.org"` for a wildcard — then **[R]etry**. Creators older than the current release could stop the walk on the CNAME chain and report CAA as fine. |
| *Required module 'DnsClient-PS' is not installed* | Run bootstrap again; it installs the module. |
| Chose Netsh but the creator says the binding is IIS-owned | Accept the offer to switch to **[W] IIS Web**. |
| Let's Encrypt rate limit | Wait. Duplicate-certificate limit is 5 per week per exact domain set. Do not loop `-Force`. |

## Daily renewal

| Symptom | What to do |
|---|---|
| *cert-secrets.json not found* | Run bootstrap again; it pulls the secrets from Key Vault. Confirm outbound HTTPS to Azure. |
| A certificate did not renew, Teams card says *failed* | Read the run log. Common causes: the `_acme-challenge` CNAME was removed, or outbound HTTPS to Let's Encrypt / Domeneshop is blocked. Fix, then `Renew-Cert.ps1 -Force` for that box or wait for the next daily run. |
| *Certificate Renewed - Post-Renewal Action Failed* card | The certificate renewed. The service restart or hook failed. Check the hook path exists, is a `.ps1`, and is writable by administrators only. |
| `Setup-AppProxy.ps1` stops with `403 Authorization_RequestDenied` | Entra refused the signed-in account. The setup needs Global Administrator or Privileged Role Administrator. If the role was activated through PIM after signing in, the token predates it: run `Disconnect-MgGraph`, then run the setup again. |
| App Proxy push failed (warning card) | The certificate is renewed locally. The daily run retries the push and reconciles on every run. If it keeps failing, re-run `Setup-AppProxy.ps1`. |
| Scripts do not seem to update | Run `Create-New-Cert.ps1`; it checks the manifest and updates. If it says it updated *itself*, run it again. |
| Log says *manifest signature refused* (event 1040) and the scripts stop updating | The scripts require a valid signature on the update manifest — missing, unreadable or wrong all refuse alike. **Certificates keep renewing normally**; only self-update stops, so this is not urgent out of hours. Tell the cert team and change nothing on the server; never download scripts by hand. The same run also reports a `manifest-unverified` line to the monitoring log, so the cert team usually sees it without being told. |
| On bootstrap: *manifest signature refused* and nothing is installed | Same cause, but during a first install there is nothing to fall back to, so bootstrap stops deliberately rather than placing unverified scripts. Nothing was changed on the server. Tell the cert team; re-run bootstrap once they confirm the manifest is fixed. |

## Linux-only

**`systemctl status certrenewal.service` says `inactive (dead)`.** That is success. The service is
`Type=oneshot`: it runs, finishes and exits. `systemctl list-timers certrenewal.timer` shows when it next
runs; `journalctl -u certrenewal.service` shows what the last run did.

**The timer fires later than 03:00.** Expected — up to an hour of deliberate jitter, so a whole fleet does
not hit Let's Encrypt at the same instant. `list-timers` shows the actual time chosen.

**A `System error` line in the journal after a run that ended `SUCCESS`.** That is PowerShell's health
channel logging exceptions the scripts *caught and handled*. If the run ended `SUCCESS`, nothing is wrong.

**A service cannot read its key.** Check the whole path, not just the file — a mode is worthless if a
parent directory cannot be traversed:

```bash
namei -l /var/lib/certrenewal/live/<domain>/privkey.pem
sudo -u www-data cat /var/lib/certrenewal/live/<domain>/privkey.pem >/dev/null && echo OK
```

`/var/lib/certrenewal` and `live/` are `0751` on purpose: traversable, but not listable. If they have been
"tidied" to `0750`, that breaks every certificate using `Files.Group`. Re-run bootstrap to repair them.
For the key itself, the service's group needs `Files.Group` **and** `PrivateMode 0640` — group ownership
alone grants nothing against a `0600` file. Most services (nginx, Apache, HAProxy) read the key as root
before dropping privileges and need neither.

**`The renewal cannot write to <directory>` (event 1046).** The nightly run is sandboxed
(`ProtectSystem=strict`) and the unit's `ReadWritePaths` is generated from `cert-config.json`, so the two
have gone out of step - almost always because the config was hand-edited and the installer was not
re-run afterwards. The run still exited 0; what is at risk is the **next** deployment to that directory.

```bash
systemctl show certrenewal.service -p ReadWritePaths   # what the unit allows
grep -i directory /etc/certrenewal/cert-config.json    # what the config asks for
sudo sh install.sh                                     # re-runnable; rewrites the unit from the config
```

If the directory belongs to a **hook** rather than to a certificate, nothing can derive it - declare it in
`/etc/systemd/system/certrenewal.service.d/10-local.conf`. See [linux.md](linux.md).

**A hook fails with `Read-only file system`.** Same cause, different symptom: the hook writes outside the
sandbox. Declare its directory in the drop-in above; do not turn the sandbox off.

**`Vault secrets sync failed: … no PEM path configured`.** The service-principal credential is not in
place. The box still renews certificates; only telemetry and the vault sync are skipped. See
[linux.md](linux.md).

**The renewal stopped self-updating.** Check the circuit breaker in
`/var/lib/certrenewal/selfupdate-state.json` and the last few runs in the journal. A refused update is
fail-closed and deliberate — report it rather than working around it.

## Before you contact the cert team

Include these and the fix is usually one message:

1. Output of `& 'C:\Cert\Renewal\Create-New-Cert.ps1' -CheckOnly` (versions, managed certificates).
2. The newest file in `C:\Cert\Renewal\log\`.
3. The exact red or yellow line you are asking about.

Back to [README.md](README.md) · [day-2-operations.md](day-2-operations.md) · [upgrade-from-v1.md](upgrade-from-v1.md)
