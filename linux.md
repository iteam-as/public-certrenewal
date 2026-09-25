# Cert-Renewal on Linux

Same tooling as the Windows guide, same certificates, same Teams and reporting — a different set of
places to put things and a different way to run them nightly. If you already know the Windows flow, the
table at the bottom is probably all you need.

| I want to… | Go to |
|---|---|
| **Set up a new Linux server** | This page. |
| Set up a Windows server | [README.md](README.md) |
| Add, change or remove a certificate | [day-2-operations.md](day-2-operations.md) |
| Something went wrong | [troubleshooting.md](troubleshooting.md), then the section at the end of this page |

---

## Quick start

```bash
curl -fsSL https://raw.githubusercontent.com/iteam-as/public-certrenewal/main/install.sh -o install.sh
sudo sh install.sh
```

That is the whole install. `install.sh` installs PowerShell if the box has none, verifies
`bootstrap.ps1` against the signed release manifest, and runs it.

Add `-DryRun` to see exactly what it *would* do without changing anything:

```bash
sudo sh install.sh -DryRun
```

---

## Before you start

- [ ] **root**, via `sudo` or a root shell.
- [ ] **A supported distribution.** Ubuntu 22.04+, Debian 12+, or RHEL 9+. Anything else works too, as
      long as **you install PowerShell 7.4 yourself first** — the installer only automates the package
      step for `apt` and `dnf`, and skips it entirely if `pwsh` is already present.
- [ ] **`curl`** and **`sha256sum`.** Present on every normal server image; the installer stops with the
      exact package command if they are missing.
- [ ] **Outbound HTTPS** to `raw.githubusercontent.com`, `packages.microsoft.com` (only if PowerShell has
      to be installed), `acme-v02.api.letsencrypt.org`, `api.domeneshop.no`, and — if telemetry is used —
      `login.microsoftonline.com` and your Key Vault.
- [ ] **The telemetry credential**, if this box should report in. See
      [The service-principal credential](#the-service-principal-credential) below. **It is optional**:
      without it the box still issues and renews certificates perfectly well.

---

## What the install does

```
== PowerShell
  not installed; this is Ubuntu 24.04.5 LTS
  fetching https://packages.microsoft.com/config/ubuntu/24.04/packages-microsoft-prod.deb
  installed: 7.4.20

== Release manifest
  https://raw.githubusercontent.com/iteam-as/public-certrenewal/main/manifest.json
  signature published - bootstrap.ps1 verifies it against the key pinned in its own source
  release 2.11.0, published 2026-09-24T09:00:00Z

== bootstrap.ps1
  sha256 verified against the manifest

== Running bootstrap
  ...
[SUCCESS] === bootstrap finished ===
```

Three things are being checked on the way in, and it is worth knowing which is which:

| Check | Done by | Hard or soft |
|---|---|---|
| `manifest.json` signature | `bootstrap.ps1`, against a key pinned in its own source | **Hard** — refuses to continue |
| `bootstrap.ps1` SHA-256 vs the manifest | `install.sh` | **Hard** — refuses to run it |
| `install.sh` itself vs the manifest | `install.sh` | Soft — warns if you are using an old copy |

The last one is a staleness check, not a security check: `install.sh` is the first thing you download, so
nothing on the box can vouch for it. That is why everything it fetches afterwards is verified.

---

## Where things end up

```
/opt/certrenewal/          0755   the scripts (they keep themselves up to date)
/etc/certrenewal/          0750   cert-config.json, cert-secrets.json
  └── keys/                0700   the service-principal private key
/var/lib/certrenewal/      0751   state
  ├── posh-acme/           0700   ACME account key + certificate keys
  ├── live/                0751   deployed certificates, one directory per domain
  └── config-backups/      0750
/var/log/certrenewal/      0750   one transcript per run, kept 90 days
```

`0751` on two of those is deliberate, not a typo: a service running as its own user has to be able to
*traverse* them to reach its key. They do not let anyone list their contents. **Do not "tidy" them to
`0750`** — that breaks every certificate using `Files.Group`, and bootstrap re-applies these modes on
every run, so it stays broken.

---

## The service-principal credential

Telemetry and the Key Vault secret sync authenticate with a certificate. Windows keeps it in the machine
certificate store; Linux has no such store, so it is a **PEM file you place yourself**:

```bash
# on a machine that has telemetry-client.pfx
openssl pkcs12 -in telemetry-client.pfx -nodes -clcerts -out telemetry-sp.pem

# on the Linux box
sudo install -o root -g root -m 0600 telemetry-sp.pem /etc/certrenewal/keys/telemetry-sp.pem
```

`-clcerts` matters: the loader takes the **first** certificate in the file, so a chain certificate landing
first would resolve the wrong identity.

If it is missing, bootstrap prints these commands and carries on. The box renews certificates normally;
only telemetry and the vault sync are skipped until you place it.

---

## The nightly run

There is no scheduled task. A **systemd timer** does the same job:

```bash
systemctl list-timers certrenewal.timer     # when it next runs, when it last ran
systemctl start certrenewal.service         # run it now, don't wait for 03:00
journalctl -u certrenewal.service -n 50     # what the last run did
journalctl CERTRENEWAL_EID=1020 --since -7d # every successful renewal this week, by event id
```

Two differences from the Windows task, both intentional:

- It fires at **03:00 plus up to an hour of jitter**, so a fleet of servers does not hit Let's Encrypt and
  Key Vault at the same instant. `list-timers` shows the actual time chosen.
- A run **missed because the box was off is caught up** on the next boot. Certificates expire on a
  calendar, not on uptime.

The service is `Type=oneshot` with no restart policy. A renewal failure is reported through Teams and
telemetry and still exits 0, so `systemctl status` showing `inactive (dead)` after a run is **success**,
not a problem.

---

## The nightly run is sandboxed

`certrenewal.service` runs with `ProtectSystem=strict`: **the whole filesystem is read-only to it except
the directories the unit names**. Those are worked out from your `cert-config.json`:

```bash
systemctl show certrenewal.service -p ReadWritePaths
```

```text
ReadWritePaths=-/etc/certrenewal -/opt/certrenewal -/var/lib/certrenewal -/var/log/certrenewal
```

The list is the four install directories, plus `SharedPoshAcmePath` if you moved it, plus **every
`Files.Directory`** your certificates deploy to — so a certificate written to `/etc/nginx/ssl/www.example.no`
adds that directory.

### The one rule: re-run bootstrap after you hand-edit the config

> If you add or move a certificate by **editing `cert-config.json` yourself**, run `sudo sh install.sh`
> afterwards. Bootstrap is re-runnable, and it rewrites the unit from the config.

`Create-New-Cert.ps1` does this for you — adding, updating or deleting a certificate rewrites the unit as
part of the flow. Only a hand edit can leave the two out of step.

If they are out of step, the renewal tells you on its **next run**, rather than letting you find out when
the certificate eventually expires:

```text
WARNING  The renewal cannot write to /etc/nginx/ssl/www.example.no. The systemd sandbox
         (ProtectSystem=strict plus ReadWritePaths in certrenewal.service) does not cover it, or the
         filesystem is read-only or full. Re-run the installer (sh install.sh) so bootstrap regenerates
         certrenewal.service from the current cert-config.json.
```

```bash
journalctl CERTRENEWAL_EID=1046 --since -7d    # every box-level sandbox warning this week
```

The run itself still completes and still exits 0 — this is a warning about the *next* deployment, not a
failed renewal. The renewal cannot repair the unit itself: `/etc/systemd/system` is deliberately not
writable from inside the sandbox.

### If a hook needs to write somewhere else

Pre- and post-renewal hooks run inside the same sandbox. A hook that writes outside the listed directories
will fail with **`Read-only file system`**. Nothing can guess what your hook touches, so declare it in a
**drop-in** — a file cert-renewal never reads and never rewrites:

```bash
sudo mkdir -p /etc/systemd/system/certrenewal.service.d
sudo tee /etc/systemd/system/certrenewal.service.d/10-local.conf >/dev/null <<'EOF'
[Service]
ReadWritePaths=-/var/lib/myapp/certs -/etc/haproxy
EOF
sudo systemctl daemon-reload
systemctl show certrenewal.service -p ReadWritePaths     # your paths are appended to the generated ones
```

Upgrades regenerate `certrenewal.service`; your drop-in survives untouched.

Two other things worth knowing about hooks here:

- **`/tmp` is private.** The service gets its own empty `/tmp`, so a hook cannot hand a file to another
  service through it. Use a directory you have declared.
- **`sudo` and setuid helpers still work** (`NoNewPrivileges` is deliberately off), and so does
  `systemctl restart …` — that was measured, not assumed.

### What is deliberately *not* locked down

`ProtectHome`, `SystemCallFilter` and `CapabilityBoundingSet` are **not set**. `ProtectHome=yes` and
`=read-only` stop PowerShell starting at all on a box where `/root/.cache` does not exist yet, and the
other two cannot be written for hooks nobody has seen — a wrong entry there would kill the run at 03:00
with no useful message. If your box runs no hooks, or you know exactly what they do, you can add them in
the same drop-in:

```ini
[Service]
ProtectHome=tmpfs
CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH CAP_FOWNER CAP_KILL CAP_SETGID CAP_SETUID
```

Test it the same evening with `sudo systemctl start certrenewal.service`, not at 03:00.

---

## Upgrades

There is nothing to do. The scripts check the signed manifest on every run and replace themselves in
place once the signature and the SHA-256 both verify; the replaced file is left `0755 root:root`.

To check now rather than waiting for 03:00:

```bash
sudo systemctl start certrenewal.service
journalctl -u certrenewal.service -n 20 --no-pager | grep -i 'up to date\|upgraded'
grep -m1 ScriptVersion /opt/certrenewal/Renew-Cert.ps1
```

To **pin** a version, set `PinVersion` in `/etc/certrenewal/cert-config.json`; the box then stays where it
is until you clear it. Re-running `install.sh` is also safe at any time — bootstrap is re-runnable, and it
repairs the layout and re-asserts the directory modes while it is there.

## Verify it worked

```bash
# the layout exists, with the modes above
ls -ld /etc/certrenewal /etc/certrenewal/keys /var/lib/certrenewal /opt/certrenewal

# the scripts arrived and are the version you expect
grep -m1 ScriptVersion /opt/certrenewal/Renew-Cert.ps1

# the timer is armed
systemctl is-enabled certrenewal.timer && systemctl list-timers certrenewal.timer

# a full dry run, changing nothing
sudo pwsh -NoProfile -File /opt/certrenewal/Renew-Cert.ps1 -DryRun
```

---

## Adding certificates

Run the creator as root:

```bash
sudo pwsh -NoProfile -File /opt/certrenewal/Create-New-Cert.ps1
```

Have the `_acme-challenge` CNAME in place first; the creator prints the exact record if it is missing.

On Linux there is only one deployment type, so there is no menu — the certificate is written to a
directory as `cert.pem`, `chain.pem`, `fullchain.pem`, `privkey.pem` and `cert.pfx`, and a service is
reloaded afterwards. The creator asks four things:

| Prompt | Default | Notes |
|---|---|---|
| **Directory** | `/var/lib/certrenewal/live/<domain>` | Anything you like — `/etc/nginx/ssl/<domain>` is common. |
| **Owner** | `root` | |
| **Group** | `root` | Set this to the service's group if it reads the key as itself. |
| **Let group *X* read the private key?** | No | **Only asked when you chose a non-root group.** |

That last question is the one worth understanding. The private key is `0600` — root only — so setting a
group on its own changes who *owns* the file and grants that group nothing. Answer **yes** and the key
becomes `0640`, which is what actually lets the service read it.

**Most services do not need it.** nginx, Apache and HAProxy all start as root, read the key, and *then*
drop privileges, so the default is right for them. Say yes only for something that runs as its own user
from the start.

Then it asks for an optional **systemd unit to reload** after each renewal — `nginx.service`, say. That
is the Linux meaning of the `RestartService` field, and it runs `systemctl reload-or-restart`.

Hooks accept **any executable**, not just PowerShell: a shell script, a binary, a Python script with a
shebang. The renewal runs them directly as root, so what matters is the execute bit — `chmod +x` it, or
the creator will tell you it did not.

## Changing or removing a certificate

```bash
sudo pwsh -NoProfile -File /opt/certrenewal/Create-New-Cert.ps1
```

**`[U]pdate`** changes where an existing certificate is deployed — directory, owner, group, key mode,
the unit to reload, hooks, renewal lead time — and re-deploys it immediately, without re-issuing.
Pressing Enter at any prompt keeps the current value. Setting a value back to its default removes it
from the config rather than storing it.

**`[D]elete`** removes the config entry, and then asks separately whether to delete the deployed files.
It defaults to **No**, because a service may still be reading them and a deleted private key is not
recoverable. The old files are left where they are unless you say otherwise.

See also [day-2-operations.md](day-2-operations.md) for the parts that are the same on both platforms.

---

## When something goes wrong

**`bad interpreter: No such file or directory`** — the copy of `install.sh` has Windows line endings.
Re-download it with `curl` rather than copying it off a Windows machine.

**`ERROR: this script needs: curl`** — install `curl` and run it again.

**`could not install PowerShell automatically on this distribution`** — not a dead end. Install
PowerShell 7.4 from the Microsoft instructions the message links to, then run `install.sh` again; it
detects `pwsh` and skips straight past that step.

**`ERROR: sha256 mismatch for bootstrap.ps1`** — the downloaded file is not what the manifest describes.
Retry once in case the download was truncated. If it persists, **report it** — do not work around it.

**`manifest signature refused`** — bootstrap will not run against a manifest it cannot verify. This is
the intended behaviour for a tampered or unsigned manifest; contact the cert team.

**`Billing block is missing and bootstrap is running non-interactively`** — you are installing from a
script, a pipe, or an automation tool, so nothing can prompt you. Pass the values instead:

```bash
sudo sh install.sh -Abr ACME -CustomerName 'Acme AS' -CustomerNr AC001 -InvoiceCode AC_001 -Services Web
```

**A `System error` line in `journalctl` after a successful run** — that is PowerShell's health channel
logging exceptions the scripts *caught and handled*. If the run ended `SUCCESS`, nothing is wrong.

---

## Windows ↔ Linux at a glance

| | Windows | Linux |
|---|---|---|
| Install | `bootstrap.ps1`, elevated | `sudo sh install.sh` |
| Scripts | `C:\Cert\Renewal` | `/opt/certrenewal` |
| Config | `C:\Cert\Renewal\cert-config.json` | `/etc/certrenewal/cert-config.json` |
| Nightly run | Scheduled task `Renew-Cert`, 03:00 | `certrenewal.timer`, 03:00 + jitter |
| Inspect it | `Get-ScheduledTask -TaskName Renew-Cert` | `systemctl list-timers certrenewal.timer` |
| Logs | Event log + `log\` | `journalctl -u certrenewal.service` + `/var/log/certrenewal/` |
| SP credential | PFX in `LocalMachine\My` | PEM at `/etc/certrenewal/keys/telemetry-sp.pem` |
| Deployment | IIS / FTP / netsh / cert store | `Files` (PEM + PFX) + a service reload |
| Elevation | Administrator | root |
| Sandbox | none (scheduled task) | `ProtectSystem=strict` + config-derived `ReadWritePaths`; widen with a `certrenewal.service.d` drop-in |
