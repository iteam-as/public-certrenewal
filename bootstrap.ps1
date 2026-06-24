#Requires -Version 5.1
<#
.SYNOPSIS
  One-shot, per-server, unattended setup + v1->v2 migration for cert-renewal v2. Run elevated, once.
.DESCRIPTION
  Plumbing (PR A): the per-server prereqs we proved by hand during Phase-2 staging, automated -
  (1) code-signing trust: download codesign.cer, verify its thumbprint against the pinned allow-list,
  install into LocalMachine Root + TrustedPublisher; (2) import the telemetry/Key Vault SP cert
  non-exportable into LocalMachine\My ("Fix B") and delete the supplied PFX; (3) machine-wide module
  install (Az.Accounts, Az.KeyVault, Posh-ACME, -Scope AllUsers, "Fix A"); (4) download + verify the
  signed Renew-Cert.ps1 AND Create-New-Cert.ps1 from the manifest, register the daily SYSTEM Renew-Cert
  task, pre-create the CertRenewal event source; (5) write the cert-config Telemetry block; pull the 4
  shared secrets from Key Vault (SP-cert auth) into cert-secrets.json (best-effort). v1->v2 migration
  (PR B): detect a v1 install and carry its domains / PaAccount / shared dir into the schema-v2 config.

  Self-contained: its helpers are COPIED VERBATIM from src/Renew-Cert.ps1 / src/Create-New-Cert.ps1 (the
  canonical sources) so the three files stay diff-able. Helpers are copied, never imported. Idempotent:
  every step is a skip-if-already-done, so re-running is safe. Bootstrap does NOT self-update (a one-shot
  tool; fetch the current copy before running). See docs/phase3-bootstrap-spec.md.
.PARAMETER TelemetryCertPfxPath
  Admin-supplied SP-cert PFX (telemetry-client.pfx). Required ONLY if the SP cert (thumbprint
  C98A9FE0...) is not already in LocalMachine\My. Imported non-exportable, then deleted from disk.
.PARAMETER TelemetryCertPassword
  Password (SecureString) for the PFX above. Required only when an import is actually performed.
.PARAMETER DryRun
  Read-only: log every "WOULD ..."; no install, import, download, migrate, write, register, or delete.
.PARAMETER ManifestUrl
  Override the manifest URL (test channel). Else the built-in prod manifest URL.
.PARAMETER CodeSignCertUrl
  Override the codesign.cer URL (test). Else the built-in prod public-mirror URL.
.PARAMETER SkipModules
  Skip the (slow) machine-wide module install (test isolation).
.PARAMETER VaultName
  Override the Key Vault name (test). Else cert-config.SecretsVault, else the built-in default.
.PARAMETER Abr
  Billing: customer abbreviation. Supply the four billing params for an unattended run; on an interactive
  run, omit them to be prompted. Required (all four) when the config has no complete Billing block.
.PARAMETER CustomerName
  Billing: full customer name.
.PARAMETER CustomerNr
  Billing: customer number.
.PARAMETER InvoiceCode
  Billing: invoice / cost-centre code.
.PARAMETER Services
  Billing: comma-separated service list (default 'CertRenewal').
.NOTES
  Source of truth : iteam-as/private-certrenewal (this repo, src/). Published (signed) to
  iteam-as/public-certrenewal by .github/workflows/release.yml on a v*.*.* tag. Do NOT edit the
  public copy by hand.
#>
[CmdletBinding()]
param(
    [string]       $TelemetryCertPfxPath,
    [securestring] $TelemetryCertPassword,
    [switch]       $DryRun,
    [string]       $ManifestUrl,
    [string]       $CodeSignCertUrl,
    [switch]       $SkipModules,
    [string]       $VaultName,
    [string]       $Abr,
    [string]       $CustomerName,
    [string]       $CustomerNr,
    [string]       $InvoiceCode,
    [string]       $Services
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue   # for DPAPI ProtectedData

# CI replaces 'DEV' with the release tag (e.g. 2.0.0) at publish time.
$ScriptVersion = '2.4.0'

# Self-signed code-signing thumbprints trusted for self-updates (array = rotation overlap).
# Enforced by THIS running script before any atomic replace; never relax via config/manifest.
# Bootstrap ALSO uses this to vet the downloaded codesign.cer before trusting it. See docs/code-signing.md.
$AllowedSignerThumbprints = @(
    '96705BBE468876FC2E48D27F3E7827500CF636E5'   # Iteam AS Cert-Renewal Code Signing (2026-06-04 .. 2036)
)

# Built-in production URLs (overridable via -ManifestUrl / -CodeSignCertUrl test channels).
$DefaultManifestUrl     = 'https://raw.githubusercontent.com/iteam-as/public-certrenewal/main/manifest.json'
$DefaultCodeSignCertUrl = 'https://raw.githubusercontent.com/iteam-as/public-certrenewal/main/codesign.cer'

# Paths (identical to Renew-Cert.ps1 / Create-New-Cert.ps1 so all three files agree).
$CertRenewalPath = 'C:\Cert\Renewal'
$ConfigPath      = Join-Path $CertRenewalPath 'cert-config.json'
$SecretsPath     = Join-Path $CertRenewalPath 'cert-secrets.json'
$RenewalScript   = Join-Path $CertRenewalPath 'Renew-Cert.ps1'
$CreatorScript   = Join-Path $CertRenewalPath 'Create-New-Cert.ps1'
$LogDir          = Join-Path $CertRenewalPath 'log'
$RenewalTaskName = 'Renew-Cert'
$SharedPoshAcmeDefault = 'C:\ProgramData\Posh-ACME'

# Azure Key Vault + telemetry SP identity (built-in; all NON-SECRET, private key stays non-exportable in
# the cert store). Same constants the creator ships (Decision D3 / docs/keyvault-secrets-setup.md section6).
$DefaultSecretsVaultName   = 'kv-online-nwe-prod-1'           # shared online-sub prod vault
$DefaultSecretsTenantId    = '8b4b76b7-fced-4075-8423-cde6771e98a7'
$TelemetryAppId            = 'b272de26-1411-441d-aa80-9853e92b238d'    # certrenewal-telemetry SP
$TelemetrySpCertThumbprint = 'C98A9FE0C362B8DC70D46B3C391BAB0C524AFFCD'
$SecretNameMap = [ordered]@{
    DomeneshopToken  = 'DomeneshopToken'
    DomeneshopSecret = 'DomeneshopSecret'
    TeamsWebhookUrl  = 'TeamsWebhookUrl'
    Email            = 'Email'
}

# Telemetry config-block identifiers (docs/telemetry-log-analytics-setup.md section6) - written into
# cert-config so the SYSTEM renewal can do SP-cert auth for both LAW ingestion and the D2 vault refresh.
$TelemetryDcrImmutableId = 'dcr-9e4de054f17e4e5c87f8fe2895967c24'
$TelemetryStream         = 'Custom-CertRenewal_CL'
$TelemetryEndpointUri    = 'https://dcr-certrenewal-og5l-norwayeast.logs.z1.ingest.monitor.azure.com'

# Windows Event Log (source shared with renewal/creator; bootstrap owns 1200-1250).
$EventLogName   = 'Application'
$EventLogSource = 'CertRenewal'
$EID = @{ Start = 1200; TrustInstalled = 1210; CertImported = 1220; ModulesInstalled = 1230; SecretsWritten = 1235; ScriptsInstalled = 1240; SelfUpdate = 1241; TaskRegistered = 1245; Migrated = 1250 }

# Read by the shared Send-Telemetry (SelfUpdateStatus column). Bootstrap does not self-update.
$SelfUpdateStatus = 'n/a'

#region Helpers copied verbatim from Renew-Cert.ps1 / Create-New-Cert.ps1 ------
# Keep these byte-identical to the canonical copies so the three files stay diff-able.

function Write-Log {
    param(
        [Parameter(Mandatory)][string] $Message,
        [ValidateSet('INFO', 'SUCCESS', 'WARNING', 'ERROR', 'DEBUG')][string] $Level = 'INFO'
    )
    $line = "[{0}] [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    switch ($Level) {
        'SUCCESS' { Write-Host $line -ForegroundColor Green }
        'WARNING' { Write-Host $line -ForegroundColor Yellow }
        'ERROR'   { Write-Host $line -ForegroundColor Red }
        'DEBUG'   { Write-Host $line -ForegroundColor Gray }
        default   { Write-Host $line }
    }
}

function Write-EventLogEntry {
    param(
        [Parameter(Mandatory)][int] $EventId,
        [ValidateSet('Information', 'Warning', 'Error')][string] $EntryType = 'Information',
        [Parameter(Mandatory)][string] $Message
    )
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists($EventLogSource)) {
            New-EventLog -LogName $EventLogName -Source $EventLogSource -ErrorAction Stop
        }
        Write-EventLog -LogName $EventLogName -Source $EventLogSource -EventId $EventId -EntryType $EntryType -Message $Message -ErrorAction Stop
    }
    catch {
        # Event Log needs admin to create the source; never fatal - transcript still captures everything.
        Write-Log "Event Log write skipped (id $EventId): $($_.Exception.Message)" -Level DEBUG
    }
}

function Unprotect-Dpapi {
    # Decrypt a base64 DPAPI-LocalMachine blob (as written by bootstrap/creator) to a UTF-8 string.
    param([string] $Base64Blob)
    if ([string]::IsNullOrWhiteSpace($Base64Blob)) { return $null }
    $bytes = [Convert]::FromBase64String($Base64Blob)
    $clear = [System.Security.Cryptography.ProtectedData]::Unprotect(
        $bytes, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
    return [System.Text.Encoding]::UTF8.GetString($clear)
}

function Protect-Dpapi {
    # Encrypt a UTF-8 string to a base64 DPAPI-LocalMachine blob (the inverse of Unprotect-Dpapi).
    param([string] $PlainText)
    # A [string] param coerces $null to '', so guard on empty (not $null) to stay the exact inverse of
    # Unprotect-Dpapi (empty/blank -> $null) - a null/empty in round-trips back to $null.
    if ([string]::IsNullOrEmpty($PlainText)) { return $null }
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($PlainText)
    $blob  = [System.Security.Cryptography.ProtectedData]::Protect(
        $bytes, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
    return [Convert]::ToBase64String($blob)
}

function Get-CertConfig {
    if (-not (Test-Path $ConfigPath)) { throw "cert-config.json not found at $ConfigPath" }
    try { return Get-Content $ConfigPath -Raw | ConvertFrom-Json }
    catch { throw "cert-config.json is not valid JSON: $($_.Exception.Message)" }
}

function Invoke-WithRetry {
    param(
        [Parameter(Mandatory)][ScriptBlock] $ScriptBlock,
        [int] $MaxRetries = 3,
        [int] $InitialDelaySeconds = 3,
        [string] $OperationName = 'Operation'
    )
    $attempt = 1; $delay = $InitialDelaySeconds
    while ($true) {
        try { return & $ScriptBlock }
        catch {
            if ($attempt -ge $MaxRetries) { throw }
            Write-Log "$OperationName attempt $attempt failed: $($_.Exception.Message). Retrying in ${delay}s..." -Level WARNING
            Start-Sleep -Seconds $delay
            $delay *= 2; $attempt++
        }
    }
}

function Test-AuthenticodeAllowed {
    # The self-update gate: the running (trusted) script vets the downloaded .new before replacing itself.
    # On the fleet the signer chain is trusted (bootstrap installs codesign.cer) so Status is Valid; the
    # thumbprint allow-list is the real anchor.
    param([Parameter(Mandatory)][string] $FilePath)
    $sig = Get-AuthenticodeSignature -FilePath $FilePath
    if (-not $sig.SignerCertificate) { return @{ Allowed = $false; Reason = 'file is not signed' } }
    $thumb = $sig.SignerCertificate.Thumbprint
    if ($AllowedSignerThumbprints -notcontains $thumb) { return @{ Allowed = $false; Reason = "signer thumbprint $thumb not in allow-list" } }
    if ($sig.Status -ne 'Valid') { return @{ Allowed = $false; Reason = "signature status is $($sig.Status)" } }
    return @{ Allowed = $true; Reason = 'ok'; Thumbprint = $thumb }
}

function Get-OnDiskScriptVersion {
    # Parse the '$ScriptVersion = ''x.y.z''' assignment from a script file. $null if absent/unreadable.
    param([Parameter(Mandatory)][string] $Path)
    if (-not (Test-Path $Path)) { return $null }
    try {
        $content = Get-Content $Path -Raw
        if ($content -match '(?m)^\s*\$ScriptVersion\s*=\s*''([^'']+)''') { return $Matches[1] }
    }
    catch { }
    return $null
}

function Save-VerifiedDownload {
    # Download $Url to a .new.ps1 sibling of $TargetPath, verify sha256 + Authenticode (allow-list),
    # then atomically Move-Item into $TargetPath. Returns the signer thumbprint. Throws on any failure.
    param(
        [Parameter(Mandatory)][string] $Url,
        [Parameter(Mandatory)][string] $ExpectedSha256,
        [Parameter(Mandatory)][string] $TargetPath,
        [string] $Label = 'script'
    )
    # The download target MUST keep a .ps1 extension: Get-AuthenticodeSignature resolves its signature
    # parser (SIP) from the extension, so a '.new' file always reads as "not signed" and the gate would
    # refuse every update (the #20 fleet bug; caught by the self-update lab).
    $newPath = Join-Path (Split-Path $TargetPath -Parent) ([IO.Path]::GetFileNameWithoutExtension($TargetPath) + '.new.ps1')
    Write-Log "Downloading $Label from $Url" -Level INFO
    Invoke-WithRetry -OperationName "$Label download" -ScriptBlock { Invoke-WebRequest -Uri $Url -OutFile $newPath -TimeoutSec 30 -UseBasicParsing } | Out-Null

    $hash = (Get-FileHash $newPath -Algorithm SHA256).Hash.ToLower()
    if ($hash -ne ([string]$ExpectedSha256).ToLower()) {
        Remove-Item $newPath -Force -ErrorAction SilentlyContinue
        throw "sha256 mismatch for $Label (downloaded $hash, manifest $ExpectedSha256)"
    }

    $auth = Test-AuthenticodeAllowed -FilePath $newPath
    if (-not $auth.Allowed) {
        Remove-Item $newPath -Force -ErrorAction SilentlyContinue
        Write-EventLogEntry $EID.SelfUpdate Error "Self-update signature refused for ${Label}: $($auth.Reason)"
        throw "signature refused for $Label ($($auth.Reason))"
    }

    Move-Item -Path $newPath -Destination $TargetPath -Force   # atomic on NTFS
    return $auth.Thumbprint
}

function Backup-CertConfig {
    # Snapshot the current cert-config.json before it is overwritten, so an admin can diff a save and see
    # what changed (and recover a prior version). Best-effort: writes to <CertRenewalPath>\config-backups\
    # cert-config.<timestamp>.<reason>.json and prunes to the newest 20. Never throws (a failed backup must
    # not block the save) and is a no-op when the file does not yet exist (first write).
    param([string] $Reason = 'config update')
    try {
        if (-not (Test-Path -LiteralPath $ConfigPath)) { return }
        $backupDir = Join-Path $CertRenewalPath 'config-backups'
        if (-not (Test-Path -LiteralPath $backupDir)) { New-Item -ItemType Directory -Path $backupDir -Force | Out-Null }
        $slug = ($Reason -replace '[^A-Za-z0-9]+', '-').Trim('-'); if (-not $slug) { $slug = 'save' }
        $dest = Join-Path $backupDir ('cert-config.{0}.{1}.json' -f (Get-Date -Format 'yyyy-MM-dd-HH_mm_ss_fff'), $slug)
        Copy-Item -LiteralPath $ConfigPath -Destination $dest -Force
        Write-Log "Backed up previous cert-config.json -> $dest" -Level DEBUG
        Get-ChildItem -LiteralPath $backupDir -Filter 'cert-config.*.json' -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending | Select-Object -Skip 20 |
            Remove-Item -Force -ErrorAction SilentlyContinue
    }
    catch { Write-Log "Could not back up cert-config.json: $($_.Exception.Message)" -Level DEBUG }
}

function Save-CertConfig {
    # Persist the (mutated) config object back to cert-config.json. DryRun-gated; never throws. Snapshots
    # the previous on-disk file to config-backups\ first (best-effort, see Backup-CertConfig).
    param([Parameter(Mandatory)][object] $Config, [string] $Reason = 'config update')
    if ($DryRun) { Write-Log "[DryRun] WOULD save cert-config.json ($Reason)." -Level INFO; return $true }
    Backup-CertConfig -Reason $Reason
    try {
        $Config | ConvertTo-Json -Depth 10 | Out-File -FilePath $ConfigPath -Force -Encoding UTF8
        Write-Log "cert-config.json saved ($Reason)." -Level SUCCESS
        return $true
    }
    catch {
        Write-Log "Failed to save cert-config.json ($Reason): $($_.Exception.Message). Continuing with in-memory configuration." -Level WARNING
        return $false
    }
}

function ConvertTo-Base64Url {
    # Base64url (JWT-safe): standard base64 with padding stripped and +/ swapped for -_.
    param([Parameter(Mandatory)][byte[]] $Bytes)
    [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function Get-TelemetryAccessToken {
    # Client-certificate assertion (RS256 JWT, no secret) -> AAD token for the Logs Ingestion scope
    # https://monitor.azure.com/.default. Same flow as the verified tools/Test-TelemetryIngestion.ps1.
    # Throws on any failure; the Send-Telemetry caller swallows it (best-effort, never blocks the caller).
    param(
        [Parameter(Mandatory)][string] $TenantId,
        [Parameter(Mandatory)][string] $AppClientId,
        [Parameter(Mandatory)][string] $CertThumbprint
    )
    $cert = Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
        Where-Object { $_.Thumbprint -eq $CertThumbprint } | Select-Object -First 1
    if (-not $cert)               { throw "telemetry cert (thumbprint $CertThumbprint) not found in LocalMachine\My" }
    if (-not $cert.HasPrivateKey) { throw "telemetry cert $CertThumbprint has no private key" }

    $now    = [DateTimeOffset]::UtcNow
    $header = @{ alg = 'RS256'; typ = 'JWT'; x5t = ConvertTo-Base64Url -Bytes $cert.GetCertHash() } | ConvertTo-Json -Compress
    $claims = @{
        aud = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
        iss = $AppClientId; sub = $AppClientId
        jti = [Guid]::NewGuid().ToString()
        nbf = $now.ToUnixTimeSeconds(); exp = $now.AddMinutes(10).ToUnixTimeSeconds()
    } | ConvertTo-Json -Compress
    $toSign = (ConvertTo-Base64Url -Bytes ([Text.Encoding]::UTF8.GetBytes($header))) + '.' +
              (ConvertTo-Base64Url -Bytes ([Text.Encoding]::UTF8.GetBytes($claims)))
    $rsa = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
    $sig = $rsa.SignData([Text.Encoding]::UTF8.GetBytes($toSign),
        [Security.Cryptography.HashAlgorithmName]::SHA256,
        [Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $jwt = $toSign + '.' + (ConvertTo-Base64Url -Bytes $sig)

    return (Invoke-RestMethod -Method Post `
        -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
        -ContentType 'application/x-www-form-urlencoded' -TimeoutSec 20 `
        -Body @{
            client_id             = $AppClientId
            scope                 = 'https://monitor.azure.com/.default'
            grant_type            = 'client_credentials'
            client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
            client_assertion      = $jwt
        }).access_token
}

function Send-Telemetry {
    # One batched POST per call to the Azure Monitor Logs Ingestion API -> CertRenewal_CL
    # (docs/telemetry-log-analytics-setup.md section 2/4). This is the fleet liveness/inventory/billing
    # signal (no periodic Teams heartbeat). BEST-EFFORT: any failure (no Telemetry config, missing cert,
    # token/POST error) logs locally and returns - it never throws and never blocks the caller, mirroring
    # the Teams "never block" rule. DryRun -> log only, no POST. SP identity + DCR coordinates come from the
    # cert-config.Telemetry block (written by bootstrap); skipped cleanly if absent/disabled.
    # SHARED VERBATIM across Renew-Cert / Create-New-Cert / bootstrap (diff-able rule). $Outcome is one OR
    # many event objects (PowerShell auto-wraps a single object); one CertRenewal_CL row is built per event
    # and ALL are sent in a single POST. $o.Action names the event (renew/create/delete/secrets-sync/
    # self-update/bootstrap/migrate/cert-renewed/service-restarted/pre-hook/post-hook/...); when omitted it
    # defaults to 'renew'. Renewal-only fields (CertCount/Certificates/NextExpiry*/Domain) and
    # $SelfUpdateStatus default cleanly when a caller doesn't set them. $o.TimeGenerated, when set,
    # preserves the event's real time (the renewal stamps each work-event when it happens); otherwise the
    # row is stamped at send time.
    param([object] $Config, [object[]] $Outcome)

    $t = $Config.Telemetry
    if (-not $t -or -not $t.Enabled) { Write-Log 'Telemetry not enabled (no cert-config.Telemetry block); skipping.' -Level DEBUG; return }
    foreach ($f in 'TenantId', 'AppClientId', 'DcrImmutableId', 'Stream', 'EndpointUri', 'CertThumbprint') {
        if ([string]::IsNullOrWhiteSpace([string]$t.$f)) { Write-Log "Telemetry block missing '$f'; skipping telemetry." -Level WARNING; return }
    }

    $billing = $Config.Billing
    $rows = foreach ($o in $Outcome) {
        $action        = if ($o.Action) { [string]$o.Action } else { 'renew' }
        $nextExpiryUtc = $null
        if ($o.NextExpiry) { try { $nextExpiryUtc = ([datetime]$o.NextExpiry).ToUniversalTime().ToString('o') } catch { } }
        $stamp         = if ($o.TimeGenerated) { [string]$o.TimeGenerated } else { (Get-Date).ToUniversalTime().ToString('o') }
        [ordered]@{
            TimeGenerated    = $stamp
            ServerName       = $env:COMPUTERNAME
            Abr              = [string]$billing.Abr
            CustomerName     = [string]$billing.CustomerName
            CustomerNr       = [string]$billing.CustomerNr
            InvoiceCode      = [string]$billing.InvoiceCode
            Service          = 'CertRenewal'
            Action           = $action
            ScriptVersion    = $ScriptVersion
            RunOutcome       = [string]$o.RunOutcome
            SelfUpdateStatus = [string]$SelfUpdateStatus
            CertCount        = [int]$o.CertCount
            NextExpiryUtc    = $nextExpiryUtc
            NextExpiryDomain = [string]$o.NextExpiryDomain
            Certificates     = @($o.Certificates | Where-Object { $_ })
            Domain           = [string]$o.Domain
            Message          = [string]$o.Message
        }
    }
    $rows = @($rows)

    if ($DryRun) {
        Write-Log ("[DryRun] WOULD emit telemetry: {0} event(s): {1}" -f `
            $rows.Count, (($rows | ForEach-Object { $_.Action }) -join ', ')) -Level INFO
        return
    }

    try {
        $token = Get-TelemetryAccessToken -TenantId $t.TenantId -AppClientId $t.AppClientId -CertThumbprint $t.CertThumbprint
        $body  = ConvertTo-Json @($rows) -Depth 6
        $uri   = "$($t.EndpointUri)/dataCollectionRules/$($t.DcrImmutableId)/streams/$($t.Stream)?api-version=2023-01-01"
        $resp  = Invoke-WebRequest -Method Post -Uri $uri -UseBasicParsing -TimeoutSec 20 `
            -Headers @{ Authorization = "Bearer $token" } -ContentType 'application/json' -Body $body
        if ($resp.StatusCode -eq 204) { Write-Log ("Telemetry accepted (204, {0} event(s))." -f $rows.Count) -Level SUCCESS }
        else { Write-Log ("Telemetry POST returned unexpected status {0}." -f $resp.StatusCode) -Level WARNING }
    }
    catch { Write-Log "Telemetry send failed (non-fatal): $($_.Exception.Message)" -Level WARNING }
}

function Connect-SecretsVault {
    # App-only sign-in to Azure with the shared telemetry SP cert (Decision D3) - same auth renewal will
    # use. No interactive admin sign-in, no fallback. Throws if a module / the cert / the connection is
    # missing. SP identity comes from the section1 built-in constants (first run has no cert-config yet).
    param(
        [string] $TenantId       = $DefaultSecretsTenantId,
        [string] $AppId          = $TelemetryAppId,
        [string] $CertThumbprint = $TelemetrySpCertThumbprint
    )
    foreach ($m in 'Az.Accounts', 'Az.KeyVault') {
        if (-not (Get-Module -ListAvailable -Name $m)) { throw "Required module '$m' is not installed (Install-Module $m)." }
    }
    Import-Module Az.Accounts -ErrorAction Stop
    Import-Module Az.KeyVault -ErrorAction Stop

    $cert = Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
        Where-Object { $_.Thumbprint -eq $CertThumbprint } | Select-Object -First 1
    if (-not $cert) {
        throw "SP cert (thumbprint $CertThumbprint) not found in LocalMachine\My - run bootstrap / install the telemetry cert first."
    }

    Invoke-WithRetry -OperationName 'Connect-AzAccount (SP cert)' -ScriptBlock {
        Connect-AzAccount -ServicePrincipal -ApplicationId $AppId -CertificateThumbprint $CertThumbprint `
            -Tenant $TenantId -ErrorAction Stop | Out-Null
    }
    Write-Log "Connected to Azure as SP $AppId (tenant $TenantId)." -Level SUCCESS
}

function Get-VaultSecretPlainText {
    # Fetch one Key Vault secret and return its plaintext (via Marshal so it works across Az versions
    # and PS 5.1 without -AsPlainText). Throws if the secret is missing.
    param([Parameter(Mandatory)][string] $VaultName, [Parameter(Mandatory)][string] $Name)
    $sec = Get-AzKeyVaultSecret -VaultName $VaultName -Name $Name -ErrorAction Stop
    if (-not $sec) { throw "Secret '$Name' not found in vault '$VaultName'." }
    $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec.SecretValue)
    try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }
}

function Set-SecretsFileAcl {
    # Restrict cert-secrets.json to Administrators + SYSTEM only (spec section4) so the SYSTEM renewal
    # task can still decrypt it. SIDs (not names) for locale independence. Never fatal.
    param([Parameter(Mandatory)][string] $Path)
    try {
        $adminSid  = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')   # BUILTIN\Administrators
        $systemSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')        # NT AUTHORITY\SYSTEM
        $acl = New-Object System.Security.AccessControl.FileSecurity
        $acl.SetAccessRuleProtection($true, $false)   # protect from inheritance, drop inherited rules
        foreach ($sid in $adminSid, $systemSid) {
            $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                $sid, 'FullControl', 'Allow')))
        }
        $acl.SetOwner($adminSid)
        Set-Acl -Path $Path -AclObject $acl
        Write-Log "  Restricted ACL on cert-secrets.json (Administrators + SYSTEM only)." -Level DEBUG
    }
    catch { Write-Log "Could not set restrictive ACL on ${Path}: $($_.Exception.Message)" -Level WARNING }
}

function Write-SecretsFile {
    # Write cert-secrets.json: the 3 secret fields DPAPI-LM-encrypted, Email plaintext (spec section4 shape).
    param([Parameter(Mandatory)][hashtable] $Values)
    $obj = [ordered]@{
        DomeneshopToken  = Protect-Dpapi $Values.DomeneshopToken
        DomeneshopSecret = Protect-Dpapi $Values.DomeneshopSecret
        TeamsWebhookUrl  = Protect-Dpapi $Values.TeamsWebhookUrl
        Email            = $Values.Email
    }
    $json = [pscustomobject]$obj | ConvertTo-Json
    [IO.File]::WriteAllText($SecretsPath, $json, (New-Object Text.UTF8Encoding($false)))   # no BOM
    Set-SecretsFileAcl -Path $SecretsPath
}

function Sync-SecretsFromVault {
    # spec section4 / Decision D. Connect to the vault (SP cert), fetch the 4 current values, and rewrite
    # cert-secrets.json IFF the file is absent or a value rotated. Idempotent (no change -> no rewrite).
    # Logs changed FIELD NAMES only, never values. Returns $true if it rewrote the file. Throws if the
    # vault is unreachable - the caller aborts before issuance (must not issue with a stale token).
    param([Parameter(Mandatory)][string] $VaultName)

    Write-Log "Syncing shared secrets from Key Vault '$VaultName'..." -Level INFO
    Connect-SecretsVault

    $fetched = @{}
    foreach ($field in $SecretNameMap.Keys) {
        $fetched[$field] = Get-VaultSecretPlainText -VaultName $VaultName -Name $SecretNameMap[$field]
    }

    # Rotation check against the locally-decrypted copy.
    $changed = @()
    if (-not (Test-Path $SecretsPath)) {
        $changed = @($SecretNameMap.Keys)
        Write-Log '  cert-secrets.json absent - will write all fields.' -Level INFO
    }
    else {
        $local = Get-Content $SecretsPath -Raw | ConvertFrom-Json
        foreach ($field in $SecretNameMap.Keys) {
            # Decrypt the local copy field-by-field. A blob written on another machine (re-image /
            # file copy) can't be decrypted by LocalMachine DPAPI and throws - treat that (and any
            # decrypt error) as "changed" so the vault value heals the broken file, rather than
            # aborting the whole sync and leaving it broken.
            $localVal = $null
            try {
                $localVal = if ($field -eq 'Email') { [string]$local.$field } else { Unprotect-Dpapi $local.$field }
            }
            catch {
                Write-Log "  Local $field could not be decrypted ($($_.Exception.Message)); treating as changed." -Level WARNING
                $changed += $field
                continue
            }
            if ([string]$fetched[$field] -ne [string]$localVal) { $changed += $field }
        }
    }

    if ($changed.Count -eq 0) {
        Write-Log '  Secrets already current - no rewrite needed.' -Level SUCCESS
        return $false
    }
    if ($DryRun) {
        Write-Log ("[DryRun] WOULD refresh cert-secrets.json (changed: {0})." -f ($changed -join ', ')) -Level INFO
        return $false
    }

    Write-SecretsFile -Values $fetched
    Write-Log ("Refreshed cert-secrets.json from vault (changed: {0})." -f ($changed -join ', ')) -Level SUCCESS
    Write-EventLogEntry $EID.SecretsWritten Information ("cert-secrets.json refreshed (fields: {0})" -f ($changed -join ', '))
    return $true
}

function Get-ResolvedVaultName {
    # -VaultName override, else cert-config.SecretsVault, else the built-in default.
    param([object] $Config)
    if ($VaultName) { return $VaultName }
    if ($Config -and $Config.SecretsVault) { return $Config.SecretsVault }
    return $DefaultSecretsVaultName
}

function Register-RenewalTask {
    # spec section7 - daily SYSTEM task running Renew-Cert.ps1 (ported verbatim from v1 ~3337-3360).
    # Removes any existing task first. DryRun-gated. Returns $true on success.
    if ($DryRun) {
        Write-Log "[DryRun] WOULD register scheduled task '$RenewalTaskName' (daily 03:00, SYSTEM, RunLevel Highest, $RenewalScript)." -Level INFO
        return $true
    }
    # Never register a task whose -File target is missing (e.g. self-update was skipped/failed and the
    # renewal script was never installed) - it would fail silently every day.
    if (-not (Test-Path $RenewalScript)) {
        Write-Log "Cannot register scheduled task: renewal script not found at $RenewalScript." -Level ERROR
        return $false
    }
    try {
        $action    = New-ScheduledTaskAction -Execute 'PowerShell.exe' -Argument "-ExecutionPolicy Bypass -NoProfile -File `"$RenewalScript`""
        $trigger   = New-ScheduledTaskTrigger -Daily -At '3:00 AM'
        $principal = New-ScheduledTaskPrincipal -UserID 'NT AUTHORITY\SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        $settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Hours 2)
        if (Get-ScheduledTask -TaskName $RenewalTaskName -ErrorAction SilentlyContinue) {
            Write-Log "Removing existing scheduled task '$RenewalTaskName'..." -Level INFO
            Unregister-ScheduledTask -TaskName $RenewalTaskName -Confirm:$false
        }
        Register-ScheduledTask -TaskName $RenewalTaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
        Write-Log "Scheduled task '$RenewalTaskName' registered (daily 03:00 as SYSTEM)." -Level SUCCESS
        Write-EventLogEntry $EID.TaskRegistered Information "Scheduled task '$RenewalTaskName' registered"
        return $true
    }
    catch {
        Write-Log "Failed to register scheduled task: $($_.Exception.Message)" -Level ERROR
        return $false
    }
}

#endregion Helpers copied verbatim --------------------------------------------

#region Bootstrap-only helpers ------------------------------------------------

function Read-Billing {
    # Prompt for the per-install Billing block (plaintext customer identifiers, not secrets). Same fields
    # and prompt strings as the creator's Read-BillingPrompts; bootstrap-native (returns a Billing object,
    # no save) because the creator's version calls creator-only helpers. Set-BootstrapBilling gates when
    # this is reached (interactive, no params, billing incomplete).
    Write-Log 'Enter the Billing block (customer identifiers stamped on Teams cards / telemetry):' -Level INFO
    $abr      = (Read-Host 'Abbreviation (Abr)').Trim()
    $custName = (Read-Host 'Customer name').Trim()
    $custNr   = (Read-Host 'Customer number').Trim()
    $invoice  = (Read-Host 'Invoice code').Trim()
    $svcRaw   = Read-Host 'Services (comma-separated) [CertRenewal]'
    $services = if ([string]::IsNullOrWhiteSpace($svcRaw)) { @('CertRenewal') }
                else { @($svcRaw -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
    return [pscustomobject][ordered]@{
        Abr = $abr; CustomerName = $custName; CustomerNr = $custNr; InvoiceCode = $invoice; Services = $services
    }
}

function Set-BootstrapBilling {
    # Force a complete Billing block onto a fresh/migrated box so telemetry/Teams are never stamped blank
    # (the gap: it otherwise stays null until someone runs the creator, which on an upgraded box may never
    # happen). Precedence: explicit -Abr/... params > an existing complete block > interactive prompt.
    # Unattended (non-interactive host) + incomplete + no params -> FATAL with a clear message (keeps the
    # no-hang unattended contract). DryRun -> log + skip. Returns the (possibly updated) config object.
    param([Parameter(Mandatory)][object] $Config)

    $b = $Config.Billing
    $complete    = $b -and $b.Abr -and $b.CustomerName -and $b.CustomerNr -and $b.InvoiceCode
    $paramsGiven = $Abr -or $CustomerName -or $CustomerNr -or $InvoiceCode -or $Services

    if ($paramsGiven) {
        foreach ($pair in @{ '-Abr' = $Abr; '-CustomerName' = $CustomerName; '-CustomerNr' = $CustomerNr; '-InvoiceCode' = $InvoiceCode }.GetEnumerator()) {
            if ([string]::IsNullOrWhiteSpace($pair.Value)) { throw "Billing parameters are incomplete: $($pair.Key) is required (supply all of -Abr/-CustomerName/-CustomerNr/-InvoiceCode)." }
        }
        $svc = if ($Services) { @($Services -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) } else { @('CertRenewal') }
        $billing = [pscustomobject][ordered]@{ Abr = $Abr; CustomerName = $CustomerName; CustomerNr = $CustomerNr; InvoiceCode = $InvoiceCode; Services = $svc }
        Write-Log "Billing block set from parameters (Customer: $CustomerName)." -Level INFO
    }
    elseif ($complete) {
        Write-Log "Billing block already present (Customer: $($b.CustomerName), Nr: $($b.CustomerNr), Invoice: $($b.InvoiceCode)); keeping it." -Level INFO
        return $Config
    }
    elseif ($DryRun) {
        Write-Log '[DryRun] WOULD prompt for the Billing block (no complete block present).' -Level INFO
        return $Config
    }
    elseif (-not [Environment]::UserInteractive) {
        throw 'Billing block is missing and bootstrap is running non-interactively. Supply -Abr/-CustomerName/-CustomerNr/-InvoiceCode (and optional -Services), or run bootstrap in an interactive session.'
    }
    else {
        $billing = Read-Billing
    }

    $Config | Add-Member -NotePropertyName 'Billing' -NotePropertyValue $billing -Force
    $null = Save-CertConfig -Config $Config -Reason 'Billing block'
    return $Config
}

function Test-IsElevated {
    # True if the current process runs with the Administrators role (required for LocalMachine cert
    # stores, machine-wide modules, the scheduled task, and the event source).
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($id)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Install-CodeSigningTrust {
    # Duty 1. Download codesign.cer, verify its thumbprint is in the pinned allow-list (NEVER install an
    # unpinned cert as a trust anchor), then import into LocalMachine\Root (chain validity) and
    # LocalMachine\TrustedPublisher (run under a restrictive policy). Idempotent per store. Must run
    # BEFORE any Save-VerifiedDownload (which requires Get-AuthenticodeSignature Status=Valid).
    param([string] $Url = $DefaultCodeSignCertUrl)
    $tmp = Join-Path $env:TEMP ("codesign-{0}.cer" -f ([guid]::NewGuid().ToString('N')))
    try {
        Write-Log "Downloading code-signing certificate from $Url" -Level INFO
        Invoke-WithRetry -OperationName 'codesign.cer download' -ScriptBlock {
            Invoke-WebRequest -Uri $Url -OutFile $tmp -TimeoutSec 30 -UseBasicParsing
        } | Out-Null
        $cert  = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $tmp
        $thumb = $cert.Thumbprint
        if ($AllowedSignerThumbprints -notcontains $thumb) {
            throw "downloaded codesign.cer thumbprint $thumb is NOT in the allow-list - refusing to install it as a trust anchor."
        }
        Write-Log "Code-signing cert thumbprint $thumb verified against the allow-list." -Level SUCCESS
        if ($DryRun) {
            Write-Log '[DryRun] WOULD import codesign.cer into LocalMachine\Root and LocalMachine\TrustedPublisher.' -Level INFO
            return
        }
        foreach ($storeName in 'Root', 'TrustedPublisher') {
            $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($storeName, 'LocalMachine')
            $store.Open('ReadWrite')
            try {
                if ($store.Certificates | Where-Object { $_.Thumbprint -eq $thumb }) {
                    Write-Log "  codesign.cer already present in LocalMachine\$storeName." -Level DEBUG
                }
                else {
                    $store.Add($cert)
                    Write-Log "  Installed codesign.cer into LocalMachine\$storeName." -Level SUCCESS
                }
            }
            finally { $store.Close() }
        }
        Write-EventLogEntry $EID.TrustInstalled Information "Code-signing trust installed ($thumb)"
    }
    finally { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
}

function Install-SpCert {
    # Duty 2 ("Fix B"). Import the telemetry/Key Vault SP cert non-exportable into LocalMachine\My, then
    # delete the supplied PFX from disk. Idempotent: skip if the thumbprint is already present. Fatal if
    # absent AND no PFX was supplied (the box can't do vault/telemetry auth without it).
    param([string] $PfxPath, [securestring] $Password)
    $existing = Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
        Where-Object { $_.Thumbprint -eq $TelemetrySpCertThumbprint } | Select-Object -First 1
    if ($existing) {
        Write-Log "SP cert $TelemetrySpCertThumbprint already present in LocalMachine\My (NotAfter $($existing.NotAfter)). Skipping import." -Level INFO
        return
    }
    if ([string]::IsNullOrWhiteSpace($PfxPath)) {
        throw "SP cert $TelemetrySpCertThumbprint is not in LocalMachine\My and no -TelemetryCertPfxPath was supplied. Supply telemetry-client.pfx (+ -TelemetryCertPassword) to bootstrap."
    }
    if (-not (Test-Path $PfxPath)) { throw "Telemetry SP-cert PFX not found at $PfxPath." }
    if ($DryRun) {
        Write-Log "[DryRun] WOULD import $PfxPath into LocalMachine\My (non-exportable) and delete the PFX." -Level INFO
        return
    }
    if (-not $Password) { throw "-TelemetryCertPassword is required to import $PfxPath." }
    $imported = Import-PfxCertificate -FilePath $PfxPath -CertStoreLocation Cert:\LocalMachine\My -Password $Password -Exportable:$false -ErrorAction Stop
    if ($imported.Thumbprint -ne $TelemetrySpCertThumbprint) {
        Write-Log "WARNING: imported PFX thumbprint $($imported.Thumbprint) != expected $TelemetrySpCertThumbprint. Continuing, but verify the correct PFX was supplied." -Level WARNING
    }
    Write-Log "Imported SP cert $($imported.Thumbprint) into LocalMachine\My (non-exportable)." -Level SUCCESS
    Write-EventLogEntry $EID.CertImported Information "Telemetry SP cert imported ($($imported.Thumbprint))"
    try {
        Remove-Item $PfxPath -Force -ErrorAction Stop
        Write-Log "Deleted the PFX from disk ($PfxPath)." -Level SUCCESS
    }
    catch { Write-Log "Could not delete the PFX at ${PfxPath}: $($_.Exception.Message). Delete it manually - it holds the private key." -Level WARNING }
}

function Install-RequiredModules {
    # Duty 3 ("Fix A", unattended). Ensure NuGet provider + PSGallery trust + TLS 1.2, then install the
    # modules the SYSTEM renewal + creator need, machine-wide (-Scope AllUsers) so the SYSTEM task can load
    # them. Born here; the creator's pending interactive "Fix A" copies this (sharing, not duplicating) and
    # wraps it with prompts. Best-effort per module: a failure warns + continues (Connect-SecretsVault /
    # Posh-ACME re-check at use; the box may still be partly usable).
    param([string[]] $Modules = @('Az.Accounts', 'Az.KeyVault', 'Posh-ACME'))
    if ($DryRun) {
        Write-Log "[DryRun] WOULD ensure NuGet + PSGallery trust + install (AllUsers): $($Modules -join ', ')." -Level INFO
        return
    }
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        if (-not (Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue)) {
            Write-Log 'Installing NuGet package provider...' -Level INFO
            Install-PackageProvider -Name NuGet -MinimumVersion '2.8.5.201' -Force -Scope AllUsers | Out-Null
        }
        if ((Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue).InstallationPolicy -ne 'Trusted') {
            Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue
        }
    }
    catch { Write-Log "Package provider / repository prep had a problem: $($_.Exception.Message). Continuing to module install." -Level WARNING }

    foreach ($m in $Modules) {
        try {
            if (Get-Module -ListAvailable -Name $m) {
                Write-Log "  Module '$m' already installed." -Level DEBUG
                continue
            }
            Write-Log "Installing module '$m' (AllUsers)..." -Level INFO
            Invoke-WithRetry -OperationName "Install-Module $m" -ScriptBlock {
                Install-Module -Name $m -Scope AllUsers -Force -AllowClobber -ErrorAction Stop
            } | Out-Null
            Write-Log "  Installed '$m'." -Level SUCCESS
        }
        catch { Write-Log "Failed to install module '${m}': $($_.Exception.Message). Continuing; the box may need a manual Install-Module." -Level WARNING }
    }
    Write-EventLogEntry $EID.ModulesInstalled Information "Required modules ensured: $($Modules -join ', ')"
}

function Install-FleetScripts {
    # Duty 4a. Download + verify (sha256 + Authenticode allow-list) the signed Renew-Cert.ps1 AND
    # Create-New-Cert.ps1 from the manifest. Renewal is REQUIRED (throws on failure -> fatal in Main); the
    # creator is best-effort (re-run bootstrap to retry). Requires the codesign trust (Duty 1) to be in
    # place first, else Save-VerifiedDownload's Authenticode gate refuses everything.
    $url = if ($ManifestUrl) { $ManifestUrl } else { $DefaultManifestUrl }
    Write-Log "Fetching manifest $url" -Level INFO
    $manifest = Invoke-WithRetry -OperationName 'manifest fetch' -ScriptBlock { Invoke-RestMethod -Uri $url -TimeoutSec 15 -UseBasicParsing }
    if (-not $manifest.renewal.version) { throw 'manifest has no renewal.version' }
    if (-not $manifest.creator.version) { throw 'manifest has no creator.version' }

    if ($DryRun) {
        Write-Log "[DryRun] WOULD download+verify Renew-Cert.ps1 $($manifest.renewal.version) and Create-New-Cert.ps1 $($manifest.creator.version)." -Level INFO
        return
    }

    $thumb = Save-VerifiedDownload -Url $manifest.renewal.url -ExpectedSha256 $manifest.renewal.sha256 -TargetPath $RenewalScript -Label 'Renew-Cert.ps1'
    Write-Log "Placed Renew-Cert.ps1 $($manifest.renewal.version) (signer $thumb)." -Level SUCCESS

    try {
        $cthumb = Save-VerifiedDownload -Url $manifest.creator.url -ExpectedSha256 $manifest.creator.sha256 -TargetPath $CreatorScript -Label 'Create-New-Cert.ps1'
        Write-Log "Placed Create-New-Cert.ps1 $($manifest.creator.version) (signer $cthumb)." -Level SUCCESS
    }
    catch { Write-Log "Create-New-Cert.ps1 download failed: $($_.Exception.Message). Renewal is in place; re-run bootstrap to retry the creator." -Level WARNING }

    Write-EventLogEntry $EID.ScriptsInstalled Information "Fleet scripts placed (renewal $($manifest.renewal.version), creator $($manifest.creator.version))"
}

function New-TelemetryBlock {
    # The cert-config Telemetry block (docs/telemetry-log-analytics-setup.md section6) - all non-secret.
    return [pscustomobject][ordered]@{
        Enabled        = $true
        TenantId       = $DefaultSecretsTenantId
        AppClientId    = $TelemetryAppId
        DcrImmutableId = $TelemetryDcrImmutableId
        Stream         = $TelemetryStream
        EndpointUri    = $TelemetryEndpointUri
        CertThumbprint = $TelemetrySpCertThumbprint
    }
}

function Set-TelemetryBlock {
    # Idempotent: add or refresh the Telemetry block on a config object (Duty 5).
    param([Parameter(Mandatory)][object] $Config)
    $Config | Add-Member -NotePropertyName 'Telemetry' -NotePropertyValue (New-TelemetryBlock) -Force
    return $Config
}

function Set-ScriptVersionStamps {
    # Bootstrap stamps BOTH versions from the freshly-placed scripts ON DISK - unlike the creator's
    # Set-ConfigVersionStamps, which stamps CreatorScriptVersion from its own $ScriptVersion (wrong here:
    # bootstrap's $ScriptVersion is the bootstrap version, not the creator's).
    param([Parameter(Mandatory)][object] $Config)
    $rv = Get-OnDiskScriptVersion -Path $RenewalScript
    $cv = Get-OnDiskScriptVersion -Path $CreatorScript
    if ($rv) { $Config | Add-Member -NotePropertyName 'RenewalScriptVersion' -NotePropertyValue $rv -Force }
    if ($cv) { $Config | Add-Member -NotePropertyName 'CreatorScriptVersion' -NotePropertyValue $cv -Force }
    return $Config
}

function New-FreshCertConfig {
    # The v2 skeleton for a fresh box (no existing config). No domains - the admin runs the creator to add
    # them. Mirrors the creator's New-DefaultCertConfig shape + the Telemetry block (Duty 5/6 fresh branch).
    $config = [pscustomobject]@{
        SchemaVersion        = 2
        RenewalScriptVersion = $null
        CreatorScriptVersion = $null
        SharedPoshAcmePath   = $SharedPoshAcmeDefault
        ManifestUrl          = $null
        PinVersion           = $null
        SecretsVault         = $null
        Billing              = $null
        Telemetry            = (New-TelemetryBlock)
        Domains              = @()
    }
    return (Set-ScriptVersionStamps -Config $config)
}

function ConvertTo-V2Config {
    # Duty 6 - map a v1 config object to the schema-v2 shape (pure; no I/O). v1 root is
    # {SharedPoshAcmePath, PaAccount, TeamsWebhookUrl, Domains}; each domain is
    # {MainDomain, Type, Guid, SANs, Thumbprint, NotAfter, +opt NetshIpPorts, RestartService} - all
    # byte-compatible with what the v2 renewal reads, so domains carry over verbatim. CARRY
    # SharedPoshAcmePath/PaAccount/Domains; DROP root TeamsWebhookUrl (now a vault secret in
    # cert-secrets.json); ADD SchemaVersion=2, version stamps, ManifestUrl/PinVersion/SecretsVault/
    # Billing=null, and the Telemetry block. Property order mirrors New-FreshCertConfig (+ PaAccount).
    param([Parameter(Mandatory)][object] $V1Config)
    $shared = if ($V1Config.SharedPoshAcmePath) { [string]$V1Config.SharedPoshAcmePath } else { $SharedPoshAcmeDefault }
    $config = [pscustomobject]@{
        SchemaVersion        = 2
        RenewalScriptVersion = $null
        CreatorScriptVersion = $null
        SharedPoshAcmePath   = $shared
        ManifestUrl          = $null
        PinVersion           = $null
        SecretsVault         = $null
        Billing              = $null
        Telemetry            = (New-TelemetryBlock)
        PaAccount            = $V1Config.PaAccount
        Domains              = @($V1Config.Domains)
    }
    return (Set-ScriptVersionStamps -Config $config)
}

function Invoke-V1Migration {
    # Duty 6 - migrate an existing v1 install. Backs up cert-config.json -> cert-config.json.pre-2.0.bak
    # (no secrets in it), converts to v2, and persists. The v1 GENERATED Renew-Cert.ps1 was already
    # replaced in place by Install-FleetScripts (Duty 4a runs BEFORE this) - deliberately NO cleartext
    # .bak of it (it embeds the hardcoded shared secrets). DryRun returns the converted object without
    # writing. Returns the v2 config object.
    param([Parameter(Mandatory)][object] $V1Config)
    $backupPath = "$ConfigPath.pre-2.0.bak"
    $domainCount = @($V1Config.Domains).Count

    if ($DryRun) {
        Write-Log "[DryRun] WOULD back up cert-config.json -> $backupPath and migrate to v2 (carry $domainCount domain(s) + PaAccount '$($V1Config.PaAccount)' + SharedPoshAcmePath; drop root TeamsWebhookUrl - now a vault secret; add SchemaVersion=2, version stamps, Telemetry block)." -Level INFO
        return (ConvertTo-V2Config -V1Config $V1Config)
    }

    try {
        Copy-Item -Path $ConfigPath -Destination $backupPath -Force
        Write-Log "Backed up v1 cert-config.json -> $backupPath" -Level SUCCESS
    }
    catch { Write-Log "Could not back up cert-config.json to ${backupPath}: $($_.Exception.Message). Continuing with the migration." -Level WARNING }

    if ($V1Config.PSObject.Properties['TeamsWebhookUrl'] -and $V1Config.TeamsWebhookUrl) {
        Write-Log '  Dropping root TeamsWebhookUrl from config (v2 reads it from cert-secrets.json, synced from the vault).' -Level INFO
    }

    $config = ConvertTo-V2Config -V1Config $V1Config
    Write-Log "Migrated config to v2: carried $domainCount domain(s)$(if ($config.PaAccount) { " + PaAccount $($config.PaAccount)" }), SharedPoshAcmePath=$($config.SharedPoshAcmePath). The v1 generated Renew-Cert.ps1 was replaced by the signed v2 download (no backup - it held hardcoded secrets)." -Level SUCCESS
    $null = Save-CertConfig -Config $config -Reason 'v1->v2 migration'
    Write-EventLogEntry $EID.Migrated Information "Migrated cert-config v1 -> v2 ($domainCount domains)"
    Send-Telemetry -Config $config -Outcome ([pscustomobject]@{ Action = 'migrate'; RunOutcome = "Migrated ($domainCount domains)" })
    return $config
}

function Initialize-CertConfig {
    # Duties 5 + 6. Write/update cert-config.json: migrate v1, top-up an existing v2, or write a fresh
    # skeleton. Every branch ensures the Telemetry block + version stamps. Returns the config object.
    $existing = if (Test-Path $ConfigPath) { Get-CertConfig } else { $null }

    if (-not $existing) {
        Write-Log 'No existing cert-config.json - writing a fresh v2 skeleton.' -Level INFO
        $config = New-FreshCertConfig
        $null = Save-CertConfig -Config $config -Reason 'fresh v2 config'
        return $config
    }

    $schema = if ($existing.PSObject.Properties['SchemaVersion']) { [int]$existing.SchemaVersion } else { 0 }
    if ($schema -ne 2) {
        Write-Log "Existing cert-config.json is v1 (SchemaVersion=$schema). Migrating to v2..." -Level WARNING
        return (Invoke-V1Migration -V1Config $existing)   # PR B
    }

    Write-Log 'Existing cert-config.json is already v2 - topping up Telemetry block + version stamps.' -Level INFO
    $config = Set-TelemetryBlock -Config $existing
    $config = Set-ScriptVersionStamps -Config $config
    $null = Save-CertConfig -Config $config -Reason 'v2 top-up (Telemetry + stamps)'
    return $config
}

function Sync-BootstrapSecrets {
    # Pull the 4 shared secrets from the vault (SP-cert auth) into cert-secrets.json. BEST-EFFORT
    # (Decision Q1): on failure, warn + continue - the box is configured; the next creator run (before
    # issuance) and the daily renewal refresh (D2) heal cert-secrets.json. A transient Azure hiccup must
    # not fail an otherwise-complete bootstrap.
    param([object] $Config)
    $vaultName = Get-ResolvedVaultName -Config $Config
    try {
        $null = Sync-SecretsFromVault -VaultName $vaultName
        Send-Telemetry -Config $Config -Outcome ([pscustomobject]@{ Action = 'bootstrap-secrets'; RunOutcome = 'Synced' })
    }
    catch {
        Write-Log "Vault secrets sync failed: $($_.Exception.Message). Continuing - the box is configured; the next creator run (before issuance) and the daily renewal refresh will heal cert-secrets.json." -Level WARNING
        Write-EventLogEntry $EID.Start Warning "Bootstrap vault secrets sync failed (best-effort): $($_.Exception.Message)"
    }
}

#endregion Bootstrap-only helpers ---------------------------------------------

#region Main ------------------------------------------------------------------

# Elevation is required before we touch LocalMachine stores / machine-wide modules / the task.
if (-not (Test-IsElevated)) {
    Write-Host 'bootstrap.ps1 must run elevated (Administrator). Re-launch in an elevated session.' -ForegroundColor Red
    exit 1
}

# Log dir + transcript rotation (keep 90 days), mirror renewal/creator. New-Item -Force creates parents.
try {
    if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
    Get-ChildItem $LogDir -Filter 'cert-bootstrap-*.log' -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-90) } | Remove-Item -Force -ErrorAction SilentlyContinue
}
catch { }

$transcriptPath = Join-Path $LogDir ("cert-bootstrap-{0}.log" -f (Get-Date -Format 'yyyy-MM-dd-HH_mm_ss'))
try { Start-Transcript -Path $transcriptPath -Append | Out-Null } catch { }

$exitCode = 0
try {
    Write-Log "=== bootstrap v$ScriptVersion starting (DryRun=$DryRun, SkipModules=$SkipModules) ===" -Level INFO
    Write-EventLogEntry $EID.Start Information "bootstrap v$ScriptVersion starting"

    if (-not (Test-Path $CertRenewalPath)) {
        if ($DryRun) { Write-Log "[DryRun] WOULD create config directory $CertRenewalPath." -Level INFO }
        else { New-Item -ItemType Directory -Path $CertRenewalPath -Force | Out-Null }
    }

    # Duty 1 - code-signing trust (MUST precede the script downloads in Duty 4a).
    Install-CodeSigningTrust -Url $(if ($CodeSignCertUrl) { $CodeSignCertUrl } else { $DefaultCodeSignCertUrl })

    # Duty 2 - SP cert import (Fix B).
    Install-SpCert -PfxPath $TelemetryCertPfxPath -Password $TelemetryCertPassword

    # Duty 3 - required modules (Fix A, unattended).
    if ($SkipModules) { Write-Log 'Module install skipped (-SkipModules).' -Level INFO }
    else { Install-RequiredModules }

    # Duty 4a - download both signed scripts (renewal required, creator best-effort).
    Install-FleetScripts

    # Duties 5 + 6 - cert-config.json (Telemetry block; migrate v1 / top-up v2 / fresh skeleton).
    $config = Initialize-CertConfig

    # Billing - force a complete block on a fresh/migrated box (params, else prompt; never blank telemetry).
    $config = Set-BootstrapBilling -Config $config

    # Secrets - pull from the vault (best-effort, Decision Q1).
    Sync-BootstrapSecrets -Config $config

    # Duty 4b - register the daily SYSTEM renewal task (event source created lazily on first Write).
    if (-not (Register-RenewalTask)) { Write-Log 'Scheduled-task registration did not complete - see the error above.' -Level WARNING }

    Send-Telemetry -Config $config -Outcome ([pscustomobject]@{ Action = 'bootstrap'; RunOutcome = 'Success' })
    Write-Log '=== bootstrap finished ===' -Level SUCCESS
}
catch {
    # Fatal failure (not elevated is handled above; here: codesign verify, required-script download, SP
    # cert absent + no PFX, config dir). Exit non-zero (spec section10).
    Write-Log "FATAL: $($_.Exception.Message)" -Level ERROR
    Write-EventLogEntry $EID.Start Error "Fatal bootstrap failure: $($_.Exception.Message)"
    $exitCode = 1
}
finally {
    try { Stop-Transcript | Out-Null } catch { }
}

exit $exitCode

#endregion Main ---------------------------------------------------------------

# SIG # Begin signature block
# MIIeDwYJKoZIhvcNAQcCoIIeADCCHfwCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAVKq0sI6kelyRY
# xXf5Io4yHqm/M8ZCbyiST7Vfx/GllqCCF6gwggRqMIIC0qADAgECAhA9a+7a4tnR
# tULR4ioNgMJCMA0GCSqGSIb3DQEBCwUAME0xCzAJBgNVBAYTAk5PMREwDwYDVQQK
# DAhJdGVhbSBBUzErMCkGA1UEAwwiSXRlYW0gQVMgQ2VydC1SZW5ld2FsIENvZGUg
# U2lnbmluZzAeFw0yNjA2MDQxMTQyMTJaFw0zNjA2MDQxMTUyMTJaME0xCzAJBgNV
# BAYTAk5PMREwDwYDVQQKDAhJdGVhbSBBUzErMCkGA1UEAwwiSXRlYW0gQVMgQ2Vy
# dC1SZW5ld2FsIENvZGUgU2lnbmluZzCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCC
# AYoCggGBANUUjgkrBhDB8TKKeXmFo+7dwNPadI/JK+BNGlBiVwKWYJey7wWkX8fg
# 5bP9JJeH//jpBPAsMCkTOa1jlCcpNz4BESjnDqosZ6oI3taoy4Srm3mVpPxh2yDf
# lAt8V5KEIZM+QZVWHEUNZU7m2Akacmo6Sb5/ORQ3lgoLVoiEmriVcebZLHMmCJdo
# AqiA63aQjyneFj6eUhfGQE9h6mAUODZWNubEPyUQF1A2DiN4toSHHaWacTL1qoda
# /mNvO34iUQckpwpKS7avSSUQijnsv3w4ITB/Hf4JgL9O5oSBWVcTCWLX0RyO0Qdp
# RE69QZGP2XZcohVc6VZllawMuJ1O3BhbAW09iycjhZGx1sPEgd5ERRQGndY/8XHA
# iW/7/yUSnRS3MKrnW8Ls2MV14EL0T08qK+300ZUWShuqM9vv8fDNoZ9NG8DGRKxm
# pqeG3pBBXsywTQ8iyl41hKodteZ3J+4uztlRyFw5sYahjIniKH5+MtS5xGWb3M2B
# gGY0gf7OOQIDAQABo0YwRDAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYB
# BQUHAwMwHQYDVR0OBBYEFF3lGiJjk0pn+ksLKLjPPTfF6PQiMA0GCSqGSIb3DQEB
# CwUAA4IBgQCyVitqOQk52FEw6oBCNfeWwKPE/ifm5TMmZaB0EOU9vabuCLjS7rF+
# o+wGD9d7EPxiG6dBmEcZ8TPudJaT2Hcvt/59Qlh3bD0gEGolpCaSjlxCEwL5QSBW
# eY48vvZkwIqMR4XOL3ZnQDYEU3LnbmihwCH18XuhHI7QB+KuLQF5F4trdTx2tfEx
# kL9ZqO7VyPVk6Sq54rol0fBeEmgLdX1oEJzf8koS2X6Kjl6kBIysDjCDDD2bRELA
# INF9rpn/D0IHeii01g9LHO+YZ6K47Mi6hUOOI0XqQgBNhNmLRdGHSJpEp8NDOHFr
# RX65ROlOCNdcazwviPnoaXLLErmwF3AeFin9E7xv1+RJTO+j92k++sB8/HspJjq3
# pBRcFQ+oQ2BK4CI7/AoEK/RKPhU2qrUDWLtOgXtoozkpWdfltoURtajsrQ2umiAA
# 8kIRWZHvrKb01RwZSMrOACRRVcBqGkRdj5zCTIIyk5EQ3l5mfL1O5Eo+9MFDP19m
# bcKkfiZWOnYwggWNMIIEdaADAgECAhAOmxiO+dAt5+/bUOIIQBhaMA0GCSqGSIb3
# DQEBDAUAMGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAX
# BgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNVBAMTG0RpZ2lDZXJ0IEFzc3Vy
# ZWQgSUQgUm9vdCBDQTAeFw0yMjA4MDEwMDAwMDBaFw0zMTExMDkyMzU5NTlaMGIx
# CzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3
# dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBH
# NDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAL/mkHNo3rvkXUo8MCIw
# aTPswqclLskhPfKK2FnC4SmnPVirdprNrnsbhA3EMB/zG6Q4FutWxpdtHauyefLK
# EdLkX9YFPFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKyunWZanMylNEQRBAu34LzB4Tm
# dDttceItDBvuINXJIB1jKS3O7F5OyJP4IWGbNOsFxl7sWxq868nPzaw0QF+xembu
# d8hIqGZXV59UWI4MK7dPpzDZVu7Ke13jrclPXuU15zHL2pNe3I6PgNq2kZhAkHnD
# eMe2scS1ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJBMtfbBHMqbpEBfCFM1LyuGwN1
# XXhm2ToxRJozQL8I11pJpMLmqaBn3aQnvKFPObURWBf3JFxGj2T3wWmIdph2PVld
# QnaHiZdpekjw4KISG2aadMreSx7nDmOu5tTvkpI6nj3cAORFJYm2mkQZK37AlLTS
# YW3rM9nF30sEAMx9HJXDj/chsrIRt7t/8tWMcCxBYKqxYxhElRp2Yn72gLD76GSm
# M9GJB+G9t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5SUUd0viastkF13nqsX40/ybzT
# QRESW+UQUOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+xq4aLT8LWRV+dIPyhHsXAj6Kx
# fgommfXkaS+YHS312amyHeUbAgMBAAGjggE6MIIBNjAPBgNVHRMBAf8EBTADAQH/
# MB0GA1UdDgQWBBTs1+OC0nFdZEzfLmc/57qYrhwPTzAfBgNVHSMEGDAWgBRF66Kv
# 9JLLgjEtUYunpyGd823IDzAOBgNVHQ8BAf8EBAMCAYYweQYIKwYBBQUHAQEEbTBr
# MCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQwYIKwYBBQUH
# MAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJ
# RFJvb3RDQS5jcnQwRQYDVR0fBD4wPDA6oDigNoY0aHR0cDovL2NybDMuZGlnaWNl
# cnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNybDARBgNVHSAECjAIMAYG
# BFUdIAAwDQYJKoZIhvcNAQEMBQADggEBAHCgv0NcVec4X6CjdBs9thbX979XB72a
# rKGHLOyFXqkauyL4hxppVCLtpIh3bb0aFPQTSnovLbc47/T/gLn4offyct4kvFID
# yE7QKt76LVbP+fT3rDB6mouyXtTP0UNEm0Mh65ZyoUi0mcudT6cGAxN3J0TU53/o
# Wajwvy8LpunyNDzs9wPHh6jSTEAZNUZqaVSwuKFWjuyk1T3osdz9HNj0d1pcVIxv
# 76FQPfx2CWiEn2/K2yCNNWAcAgPLILCsWKAOQGPFmCLBsln1VWvPJ6tsds5vIy30
# fnFqI2si/xK4VC0nftg62fC2h5b9W9FcrBjDTZ9ztwGpn1eqXijiuZQwgga0MIIE
# nKADAgECAhANx6xXBf8hmS5AQyIMOkmGMA0GCSqGSIb3DQEBCwUAMGIxCzAJBgNV
# BAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdp
# Y2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDAeFw0y
# NTA1MDcwMDAwMDBaFw0zODAxMTQyMzU5NTlaMGkxCzAJBgNVBAYTAlVTMRcwFQYD
# VQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBH
# NCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTEwggIiMA0GCSqG
# SIb3DQEBAQUAA4ICDwAwggIKAoICAQC0eDHTCphBcr48RsAcrHXbo0ZodLRRF51N
# rY0NlLWZloMsVO1DahGPNRcybEKq+RuwOnPhof6pvF4uGjwjqNjfEvUi6wuim5ba
# p+0lgloM2zX4kftn5B1IpYzTqpyFQ/4Bt0mAxAHeHYNnQxqXmRinvuNgxVBdJkf7
# 7S2uPoCj7GH8BLuxBG5AvftBdsOECS1UkxBvMgEdgkFiDNYiOTx4OtiFcMSkqTtF
# 2hfQz3zQSku2Ws3IfDReb6e3mmdglTcaarps0wjUjsZvkgFkriK9tUKJm/s80Fio
# cSk1VYLZlDwFt+cVFBURJg6zMUjZa/zbCclF83bRVFLeGkuAhHiGPMvSGmhgaTzV
# yhYn4p0+8y9oHRaQT/aofEnS5xLrfxnGpTXiUOeSLsJygoLPp66bkDX1ZlAeSpQl
# 92QOMeRxykvq6gbylsXQskBBBnGy3tW/AMOMCZIVNSaz7BX8VtYGqLt9MmeOreGP
# RdtBx3yGOP+rx3rKWDEJlIqLXvJWnY0v5ydPpOjL6s36czwzsucuoKs7Yk/ehb//
# Wx+5kMqIMRvUBDx6z1ev+7psNOdgJMoiwOrUG2ZdSoQbU2rMkpLiQ6bGRinZbI4O
# Lu9BMIFm1UUl9VnePs6BaaeEWvjJSjNm2qA+sdFUeEY0qVjPKOWug/G6X5uAiynM
# 7Bu2ayBjUwIDAQABo4IBXTCCAVkwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4E
# FgQU729TSunkBnx6yuKQVvYv1Ensy04wHwYDVR0jBBgwFoAU7NfjgtJxXWRM3y5n
# P+e6mK4cD08wDgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMIMHcG
# CCsGAQUFBwEBBGswaTAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQu
# Y29tMEEGCCsGAQUFBzAChjVodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGln
# aUNlcnRUcnVzdGVkUm9vdEc0LmNydDBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8v
# Y3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNybDAgBgNV
# HSAEGTAXMAgGBmeBDAEEAjALBglghkgBhv1sBwEwDQYJKoZIhvcNAQELBQADggIB
# ABfO+xaAHP4HPRF2cTC9vgvItTSmf83Qh8WIGjB/T8ObXAZz8OjuhUxjaaFdleMM
# 0lBryPTQM2qEJPe36zwbSI/mS83afsl3YTj+IQhQE7jU/kXjjytJgnn0hvrV6hqW
# Gd3rLAUt6vJy9lMDPjTLxLgXf9r5nWMQwr8Myb9rEVKChHyfpzee5kH0F8HABBgr
# 0UdqirZ7bowe9Vj2AIMD8liyrukZ2iA/wdG2th9y1IsA0QF8dTXqvcnTmpfeQh35
# k5zOCPmSNq1UH410ANVko43+Cdmu4y81hjajV/gxdEkMx1NKU4uHQcKfZxAvBAKq
# MVuqte69M9J6A47OvgRaPs+2ykgcGV00TYr2Lr3ty9qIijanrUR3anzEwlvzZiiy
# fTPjLbnFRsjsYg39OlV8cipDoq7+qNNjqFzeGxcytL5TTLL4ZaoBdqbhOhZ3ZRDU
# phPvSRmMThi0vw9vODRzW6AxnJll38F0cuJG7uEBYTptMSbhdhGQDpOXgpIUsWTj
# d6xpR6oaQf/DJbg3s6KCLPAlZ66RzIg9sC+NJpud/v4+7RWsWCiKi9EOLLHfMR2Z
# yJ/+xhCx9yHbxtl5TPau1j/1MIDpMPx0LckTetiSuEtQvLsNz3Qbp7wGWqbIiOWC
# nb5WqxL3/BAPvIXKUjPSxyZsq8WhbaM2tszWkPZPubdcMIIG7TCCBNWgAwIBAgIQ
# CoDvGEuN8QWC0cR2p5V0aDANBgkqhkiG9w0BAQsFADBpMQswCQYDVQQGEwJVUzEX
# MBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0
# ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExMB4XDTI1
# MDYwNDAwMDAwMFoXDTM2MDkwMzIzNTk1OVowYzELMAkGA1UEBhMCVVMxFzAVBgNV
# BAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBTSEEyNTYgUlNB
# NDA5NiBUaW1lc3RhbXAgUmVzcG9uZGVyIDIwMjUgMTCCAiIwDQYJKoZIhvcNAQEB
# BQADggIPADCCAgoCggIBANBGrC0Sxp7Q6q5gVrMrV7pvUf+GcAoB38o3zBlCMGMy
# qJnfFNZx+wvA69HFTBdwbHwBSOeLpvPnZ8ZN+vo8dE2/pPvOx/Vj8TchTySA2R4Q
# KpVD7dvNZh6wW2R6kSu9RJt/4QhguSssp3qome7MrxVyfQO9sMx6ZAWjFDYOzDi8
# SOhPUWlLnh00Cll8pjrUcCV3K3E0zz09ldQ//nBZZREr4h/GI6Dxb2UoyrN0ijtU
# DVHRXdmncOOMA3CoB/iUSROUINDT98oksouTMYFOnHoRh6+86Ltc5zjPKHW5KqCv
# pSduSwhwUmotuQhcg9tw2YD3w6ySSSu+3qU8DD+nigNJFmt6LAHvH3KSuNLoZLc1
# Hf2JNMVL4Q1OpbybpMe46YceNA0LfNsnqcnpJeItK/DhKbPxTTuGoX7wJNdoRORV
# bPR1VVnDuSeHVZlc4seAO+6d2sC26/PQPdP51ho1zBp+xUIZkpSFA8vWdoUoHLWn
# qWU3dCCyFG1roSrgHjSHlq8xymLnjCbSLZ49kPmk8iyyizNDIXj//cOgrY7rlRyT
# laCCfw7aSUROwnu7zER6EaJ+AliL7ojTdS5PWPsWeupWs7NpChUk555K096V1hE0
# yZIXe+giAwW00aHzrDchIc2bQhpp0IoKRR7YufAkprxMiXAJQ1XCmnCfgPf8+3mn
# AgMBAAGjggGVMIIBkTAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBTkO/zyMe39/dfz
# kXFjGVBDz2GM6DAfBgNVHSMEGDAWgBTvb1NK6eQGfHrK4pBW9i/USezLTjAOBgNV
# HQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwgZUGCCsGAQUFBwEB
# BIGIMIGFMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wXQYI
# KwYBBQUHMAKGUWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRy
# dXN0ZWRHNFRpbWVTdGFtcGluZ1JTQTQwOTZTSEEyNTYyMDI1Q0ExLmNydDBfBgNV
# HR8EWDBWMFSgUqBQhk5odHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRU
# cnVzdGVkRzRUaW1lU3RhbXBpbmdSU0E0MDk2U0hBMjU2MjAyNUNBMS5jcmwwIAYD
# VR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEBCwUAA4IC
# AQBlKq3xHCcEua5gQezRCESeY0ByIfjk9iJP2zWLpQq1b4URGnwWBdEZD9gBq9fN
# aNmFj6Eh8/YmRDfxT7C0k8FUFqNh+tshgb4O6Lgjg8K8elC4+oWCqnU/ML9lFfim
# 8/9yJmZSe2F8AQ/UdKFOtj7YMTmqPO9mzskgiC3QYIUP2S3HQvHG1FDu+WUqW4da
# IqToXFE/JQ/EABgfZXLWU0ziTN6R3ygQBHMUBaB5bdrPbF6MRYs03h4obEMnxYOX
# 8VBRKe1uNnzQVTeLni2nHkX/QqvXnNb+YkDFkxUGtMTaiLR9wjxUxu2hECZpqyU1
# d0IbX6Wq8/gVutDojBIFeRlqAcuEVT0cKsb+zJNEsuEB7O7/cuvTQasnM9AWcIQf
# VjnzrvwiCZ85EE8LUkqRhoS3Y50OHgaY7T/lwd6UArb+BOVAkg2oOvol/DJgddJ3
# 5XTxfUlQ+8Hggt8l2Yv7roancJIFcbojBcxlRcGG0LIhp6GvReQGgMgYxQbV1S3C
# rWqZzBt1R9xJgKf47CdxVRd/ndUlQ05oxYy2zRWVFjF7mcr4C34Mj3ocCVccAvlK
# V9jEnstrniLvUxxVZE/rptb7IRE2lskKPIJgbaP5t2nGj/ULLi49xTcBZU8atufk
# +EMF/cWuiC7POGT75qaL6vdCvHlshtjdNXOCIUjsarfNZzGCBb0wggW5AgEBMGEw
# TTELMAkGA1UEBhMCTk8xETAPBgNVBAoMCEl0ZWFtIEFTMSswKQYDVQQDDCJJdGVh
# bSBBUyBDZXJ0LVJlbmV3YWwgQ29kZSBTaWduaW5nAhA9a+7a4tnRtULR4ioNgMJC
# MA0GCWCGSAFlAwQCAQUAoIGEMBgGCisGAQQBgjcCAQwxCjAIoAKAAKECgAAwGQYJ
# KoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQB
# gjcCARUwLwYJKoZIhvcNAQkEMSIEIJ9AOPoWnOSahnc0zIKw20nBG8ciNTcm5nVt
# BpEl8AoqMA0GCSqGSIb3DQEBAQUABIIBgFqkIXrWYqajbPo90Qr67a/Pt8T6HH64
# OJ59u9dR2a8aEViqKbq95p2pycveYlBBSdqsfvqCgX8vhs8Uwqv8LXnEV2yQBv/w
# 0uGqbKooH26G1Vp68gGwtLwp/8dIMS8hkjsBgaIoc4dEJtijHsLF4UxqwrI5y6xE
# mIV4+y7s/cgq191E8qJwyPyTXbWKcXJmTdZA8+qyd+pUKuQUKWHPuOp9JRB0fioA
# W757Fh+SIjeh620rYPKW+11WaYIWo0H906ADRiPgBbvyphpSrQYxvnKRMjL5MV+u
# xP7NXcGwxnU1T8p9/i46KnFvqNGvDQZienKHQccIfHRecVESnde0qoWVmqk/cvSb
# 6725n0gf54Lf/4YL0cbi9hv4/pvuMQ3aPFx7v215kI6DCBa3YIayelEJRR8aBMbX
# PGFUAe88QAQJajZTMEADyMLwF9BUTzPiD6Jlku26Xq6dvwp1DjfVw/xEg9/hrRkv
# XOKxp8JgKfTD6aFjF7VHNyOtMHddhJBrBKGCAyYwggMiBgkqhkiG9w0BCQYxggMT
# MIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5j
# LjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNB
# NDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZIAWUD
# BAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEP
# Fw0yNjA2MjQxMDMzNTNaMC8GCSqGSIb3DQEJBDEiBCCrtTo9G0NTBRX6BUOegoI6
# D2jfCfExo//nIABM26vEcDANBgkqhkiG9w0BAQEFAASCAgAarW8EWr3TbxSQ1yE8
# lPAaLab81/Tz/8iyZTrKGx/FgDalBk0r7PQ1oAfVC48zlrx6lHulLg/YH0nyZrzv
# 9FWp71xt610HEuwSlylP3dKNlqVCbUkSGWMasISFFmqvWkqAbPqrC037YWgRYCAM
# 8KigRPCwC7HnhYlOhduhXAvqlppyiBJZzvaxYN28C4qmOdBKWPKwCcJau9mAxY0m
# d214cPv5/M4Evp7XmThgO0hg22GN4zEevC/jYUOOkoVwwxHYZQepEHJzZG8QYpyX
# 89O6X98D4WEEjinVbbrg7S9fNrCvFO2CvU5DMqZpSd/NALfFgKnLFqdrrFGfd3DM
# DgfY044tLpjfH9DFghY0QNHa0TMMKZPTJ9wIynCKMqS60VlUmOXcFoqAMffAbmGg
# Bg6fGghsB8OxQtDCO561IKilkb0NSDLdhjG8HgBqVYGlMVZ3Fe5ZPzKp6YHndAnk
# lUD3vfMfpEI/6mn49wCgJjOol3azIOehMMJr2/NNJZ7M9JLI9fNCCAusrQJOnn8b
# tjo9l/UyAul4rulMCbUmv6k4bdGKrSnM2ygjbCJ14txfujzC6ehpQIf+OIpcttKk
# QlVbeYxj1Ie6lLvfmp0OM1ujDWNVAzMy0v/SiIITjrCtPLMhXL9mflv946FHz+94
# P5uKbqZpesvruX5NJPO+6H7Kdg==
# SIG # End signature block
