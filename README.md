# public-certrenewal

> ⚠️ **CI-managed artifact mirror — DO NOT EDIT BY HAND.**
>
> Every file here is generated and published by CI from the private source repo
> on each tagged release. Any manual change will be **silently overwritten** by
> the next release. Open issues and PRs against the source repo instead.

This repository hosts the **signed, hashed, published** scripts that the
cert-renewal fleet downloads over HTTPS. It is the canonical artifact location
referenced by `manifest.json`.

## What lives here (after the first release)

| File | Purpose |
|------|---------|
| `manifest.json` | Source of truth for the current version + sha256 + raw URL of each script. |
| `Create-New-Cert.ps1` | Creator / cert-add tool (signed). |
| `Renew-Cert.ps1` | Daily renewal + self-update + heartbeat (signed). |
| `bootstrap.ps1` | One-shot migration for existing servers (signed). |

Fleet URLs are stable because the layout is flat at the repo root, e.g.:

```
https://raw.githubusercontent.com/iteam-as/public-certrenewal/main/manifest.json
https://raw.githubusercontent.com/iteam-as/public-certrenewal/main/Renew-Cert.ps1
```

## Source & release process

- **Source of truth:** `iteam-as/private-certrenewal` (private). All editing, PRs,
  review, and history live there.
- **Publish trigger:** pushing a `v*.*.*` tag on the private repo's reviewed `main`.
  CI validates (AST parse) → stamps the version → Authenticode-signs → computes
  sha256 → renders `manifest.json` → pushes here.
- **Integrity:** every script is Authenticode-signed (Azure Trusted Signing) and
  sha256-pinned in the manifest. Servers verify both before replacing the live copy.
- **Tamper recovery:** if this repo is altered, the next tagged release overwrites it.
- **Rollback:** tag an earlier source commit to republish older code as current.
