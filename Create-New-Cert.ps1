#Requires -Version 5.1
<#
.SYNOPSIS
  Interactive creator / admin tool for cert-renewal v2. Run elevated by an administrator.
.DESCRIPTION
  Plumbing (PR A): two-script self-update (installs/updates the signed Renew-Cert.ps1 from the
  manifest AND updates itself, then halts for re-run), pull-and-DPAPI-LM-encrypt the 4 shared secrets
  from Azure Key Vault into cert-secrets.json (SP-cert app-only auth), the per-install Billing prompt,
  scheduled-task registration, local logging (transcript + Windows Event Log) and a Send-Telemetry
  stub. Issuance (PR B): the interactive Add/Delete/Update menu, DNS-01/CAA validation, Posh-ACME
  account setup and New-PACertificate issuance + per-Type binding deploy via the shared renewal family.

  Self-contained: its own copy of the shared helpers (Write-Log, Compare-SemVer, the self-update
  routine, DPAPI, ...) copied verbatim from src/Renew-Cert.ps1 (the canonical implementation) so the
  two files stay diff-able. Helpers are copied, never imported.
.PARAMETER DryRun
  Read-only: log what WOULD happen; no self-update replace, no secrets write, no issue/deploy/register.
.PARAMETER ManifestUrl
  Override the manifest URL (test channel). Else cert-config.ManifestUrl, else the built-in prod URL.
.PARAMETER SkipSelfUpdate
  Skip the two-script self-update check (test isolation).
.PARAMETER CheckOnly
  Print versions + cert inventory + secrets-present status and exit (no menu).
.PARAMETER VaultName
  Override the Key Vault name (test). Else cert-config.SecretsVault, else the built-in default.
.NOTES
  Source of truth : iteam-as/private-certrenewal (this repo, src/). Published (signed) to
  iteam-as/public-certrenewal by .github/workflows/release.yml on a v*.*.* tag. Do NOT edit the
  public copy by hand.
#>
[CmdletBinding()]
param(
    [switch] $DryRun,
    [string] $ManifestUrl,
    [switch] $SkipSelfUpdate,
    [switch] $CheckOnly,
    [string] $VaultName
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue   # for DPAPI ProtectedData

# CI replaces 'DEV' with the release tag (e.g. 2.0.0) at publish time.
$ScriptVersion = '2.0.1'

# Self-signed code-signing thumbprints trusted for self-updates (array = rotation overlap).
# Enforced by THIS running script before any atomic replace; never relax via config/manifest.
# See docs/code-signing.md. (Identical allow-list to Renew-Cert.ps1.)
$AllowedSignerThumbprints = @(
    '96705BBE468876FC2E48D27F3E7827500CF636E5'   # Iteam AS Cert-Renewal Code Signing (2026-06-04 .. 2036)
)

# Built-in production manifest URL (overridable via -ManifestUrl or cert-config.ManifestUrl test channel).
$DefaultManifestUrl = 'https://raw.githubusercontent.com/iteam-as/public-certrenewal/main/manifest.json'

# Paths (identical to Renew-Cert.ps1 so both files agree).
$CertRenewalPath = 'C:\Cert\Renewal'
$ConfigPath      = Join-Path $CertRenewalPath 'cert-config.json'
$SecretsPath     = Join-Path $CertRenewalPath 'cert-secrets.json'
$RenewalScript   = Join-Path $CertRenewalPath 'Renew-Cert.ps1'
$SelfUpdateState = Join-Path $CertRenewalPath 'selfupdate-state.json'
$LogDir          = Join-Path $CertRenewalPath 'log'
$SelfPath        = $PSCommandPath        # this script's own path, for the atomic self-replace
$RenewalTaskName = 'Renew-Cert'
$SharedPoshAcmeDefault = 'C:\ProgramData\Posh-ACME'

# Azure Key Vault holding the 4 shared secrets (spec section4). Built-in default; cert-config.SecretsVault
# or -VaultName override. SP identity ships as built-in constants so first run (no cert-config yet) can
# authenticate; all values are NON-SECRET (private key stays non-exportable in LocalMachine\My).
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

# Windows Event Log (source shared with renewal; creator owns 1100-1150, renewal owns 1000-1050).
$EventLogName   = 'Application'
$EventLogSource = 'CertRenewal'
$EID = @{ Start = 1100; SecretsWritten = 1110; CertIssued = 1120; CertDeleted = 1130; TaskRegistered = 1140; SelfUpdate = 1150 }

# Read by the shared Send-Telemetry (SelfUpdateStatus column). The creator reports its own self-update via
# the 'self-update' event's RunOutcome; this default keeps the field defined for its other events.
$SelfUpdateStatus = 'Skipped'

#region Helpers copied verbatim from Renew-Cert.ps1 ---------------------------
# Keep these byte-identical to the renewal copies so the two files stay diff-able.

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

function Get-CertConfig {
    if (-not (Test-Path $ConfigPath)) { throw "cert-config.json not found at $ConfigPath" }
    try { return Get-Content $ConfigPath -Raw | ConvertFrom-Json }
    catch { throw "cert-config.json is not valid JSON: $($_.Exception.Message)" }
}

function Get-Secrets {
    if (-not (Test-Path $SecretsPath)) { throw "cert-secrets.json not found at $SecretsPath (run bootstrap/creator first)" }
    $raw = Get-Content $SecretsPath -Raw | ConvertFrom-Json
    return [pscustomobject]@{
        DomeneshopToken  = Unprotect-Dpapi $raw.DomeneshopToken
        DomeneshopSecret = Unprotect-Dpapi $raw.DomeneshopSecret   # PR B wraps as SecureString for Posh-ACME
        TeamsWebhookUrl  = Unprotect-Dpapi $raw.TeamsWebhookUrl
        Email            = $raw.Email
    }
}

function Compare-SemVer {
    # Returns -1 if A<B, 0 if equal, 1 if A>B. Non-semver (e.g. 'DEV') sorts as oldest (0.0.0),
    # so a 'DEV' build always treats a published version as newer. Prerelease suffix is ignored for ordering.
    param([string] $A, [string] $B)
    function ConvertTo-Ver([string] $v) {
        if ($v -match '^(\d+)\.(\d+)\.(\d+)') { return [version]("{0}.{1}.{2}" -f $Matches[1], $Matches[2], $Matches[3]) }
        return [version]'0.0.0'
    }
    $va = ConvertTo-Ver $A; $vb = ConvertTo-Ver $B
    if ($va -lt $vb) { return -1 } elseif ($va -gt $vb) { return 1 } else { return 0 }
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
    # The self-update gate: the running (trusted) script vets a downloaded .new before placing it.
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

function Get-SelfUpdateState {
    if (Test-Path $SelfUpdateState) {
        try { return Get-Content $SelfUpdateState -Raw | ConvertFrom-Json } catch { }
    }
    return [pscustomobject]@{ consecutiveFailures = 0; lastAttemptUtc = $null }
}

function Save-SelfUpdateState {
    param([Parameter(Mandatory)] $State)
    try { $State | ConvertTo-Json | Set-Content -Path $SelfUpdateState -Encoding UTF8 }
    catch { Write-Log "Could not save self-update state: $($_.Exception.Message)" -Level DEBUG }
}

function Save-CertConfig {
    # Persist the (mutated) config object back to cert-config.json. DryRun-gated; never throws.
    param([Parameter(Mandatory)][object] $Config, [string] $Reason = 'config update')
    if ($DryRun) { Write-Log "[DryRun] WOULD save cert-config.json ($Reason)." -Level INFO; return $true }
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
    # One structured event per run to the Azure Monitor Logs Ingestion API -> CertRenewal_CL
    # (docs/telemetry-log-analytics-setup.md section 2/4). This is the fleet liveness/inventory/billing
    # signal (no periodic Teams heartbeat). BEST-EFFORT: any failure (no Telemetry config, missing cert,
    # token/POST error) logs locally and returns - it never throws and never blocks the caller, mirroring
    # the Teams "never block" rule. DryRun -> log only, no POST. SP identity + DCR coordinates come from the
    # cert-config.Telemetry block (written by bootstrap); skipped cleanly if absent/disabled.
    # SHARED VERBATIM across Renew-Cert / Create-New-Cert / bootstrap (diff-able rule): $Outcome.Action
    # names the event (renew/create/delete/secrets-sync/self-update/bootstrap/migrate/...); renewal omits it
    # (defaults to 'renew'). Renewal-only fields (CertCount/Certificates/NextExpiry*) and $SelfUpdateStatus
    # default cleanly when a caller doesn't set them.
    param([object] $Config, [object] $Outcome)

    $t = $Config.Telemetry
    if (-not $t -or -not $t.Enabled) { Write-Log 'Telemetry not enabled (no cert-config.Telemetry block); skipping.' -Level DEBUG; return }
    foreach ($f in 'TenantId', 'AppClientId', 'DcrImmutableId', 'Stream', 'EndpointUri', 'CertThumbprint') {
        if ([string]::IsNullOrWhiteSpace([string]$t.$f)) { Write-Log "Telemetry block missing '$f'; skipping telemetry." -Level WARNING; return }
    }

    $billing       = $Config.Billing
    $action        = if ($Outcome.Action) { [string]$Outcome.Action } else { 'renew' }
    $nextExpiryUtc = $null
    if ($Outcome.NextExpiry) { try { $nextExpiryUtc = ([datetime]$Outcome.NextExpiry).ToUniversalTime().ToString('o') } catch { } }

    $row = [ordered]@{
        TimeGenerated    = (Get-Date).ToUniversalTime().ToString('o')
        ServerName       = $env:COMPUTERNAME
        Abr              = [string]$billing.Abr
        CustomerName     = [string]$billing.CustomerName
        CustomerNr       = [string]$billing.CustomerNr
        InvoiceCode      = [string]$billing.InvoiceCode
        Service          = 'CertRenewal'
        Action           = $action
        ScriptVersion    = $ScriptVersion
        RunOutcome       = [string]$Outcome.RunOutcome
        SelfUpdateStatus = [string]$SelfUpdateStatus
        CertCount        = [int]$Outcome.CertCount
        NextExpiryUtc    = $nextExpiryUtc
        NextExpiryDomain = [string]$Outcome.NextExpiryDomain
        Certificates     = @($Outcome.Certificates | Where-Object { $_ })
        Message          = [string]$Outcome.Message
    }

    if ($DryRun) {
        Write-Log ("[DryRun] WOULD emit telemetry: action={0} server={1} outcome={2} certs={3}" -f `
            $row.Action, $row.ServerName, $row.RunOutcome, $row.CertCount) -Level INFO
        return
    }

    try {
        $token = Get-TelemetryAccessToken -TenantId $t.TenantId -AppClientId $t.AppClientId -CertThumbprint $t.CertThumbprint
        $body  = ConvertTo-Json @($row) -Depth 6
        $uri   = "$($t.EndpointUri)/dataCollectionRules/$($t.DcrImmutableId)/streams/$($t.Stream)?api-version=2023-01-01"
        $resp  = Invoke-WebRequest -Method Post -Uri $uri -UseBasicParsing -TimeoutSec 20 `
            -Headers @{ Authorization = "Bearer $token" } -ContentType 'application/json' -Body $body
        if ($resp.StatusCode -eq 204) { Write-Log "Telemetry event accepted (204, action=$($row.Action))." -Level SUCCESS }
        else { Write-Log ("Telemetry POST returned unexpected status {0}." -f $resp.StatusCode) -Level WARNING }
    }
    catch { Write-Log "Telemetry send failed (non-fatal): $($_.Exception.Message)" -Level WARNING }
}

function Get-DomainSuffix {
    # Extract apex/registrable domain suffix (handles wildcards and apex domains).
    param([string] $FQDN)
    if ($FQDN -match '^\*\.(.+)$') { return $Matches[1] }
    $dotIndex = $FQDN.IndexOf('.')
    if ($dotIndex -le 0 -or $dotIndex -ge ($FQDN.Length - 1)) { throw "Invalid FQDN format: $FQDN" }
    # Apex domains (e.g. example.no) have only one dot - return as-is
    $dotCount = ($FQDN.ToCharArray() | Where-Object { $_ -eq '.' }).Count
    if ($dotCount -eq 1) { return $FQDN }
    return $FQDN.Substring($dotIndex + 1)
}

function Get-AcmeChallengeDomain {
    # Compute the ACME DNS-01 challenge record name.
    param([string] $Domain)
    if ($Domain -match '^\*\.(.+)$') { return "_acme-challenge.$($Matches[1])" }
    return "_acme-challenge.$Domain"
}

function Get-StoreCertificateForDomain {
    # Most recent (preferring non-expired) LocalMachine\My certificate whose CN or SANs cover $Domain.
    param([string] $Domain)
    $escapedDomain = [regex]::Escape($Domain)
    $existingCerts = @(Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue | Where-Object {
        ($_.Subject -match "CN\s*=\s*$escapedDomain\b") -or ($_.DnsNameList.Unicode -contains $Domain)
    } | Sort-Object NotAfter -Descending)
    if ($existingCerts.Count -eq 0) { return $null }
    $validCert = $existingCerts | Where-Object { $_.NotAfter -gt (Get-Date) } | Select-Object -First 1
    if (-not $validCert) { $validCert = $existingCerts | Select-Object -First 1 }
    return $validCert
}

function Get-NetshSslBindings {
    # Parse `netsh http show sslcert` into objects. SNI bindings ("Hostname:port") must be rebound
    # with hostnameport= (and certstorename=MY); IP bindings ("IP:port") with ipport=.
    $allBindings = netsh http show sslcert 2>&1
    $bindingInfo = @()
    $currentBinding = @{}
    foreach ($line in $allBindings) {
        if ($line -match 'IP:port\s*:\s*(.+)') {
            if ($currentBinding.Count -gt 0) { $bindingInfo += [pscustomobject]$currentBinding }
            $currentBinding = @{ IpPort = $Matches[1].Trim(); BindingKey = 'ipport'; CertHash = $null; AppId = $null }
        }
        elseif ($line -match 'Hostname:port\s*:\s*(.+)') {
            if ($currentBinding.Count -gt 0) { $bindingInfo += [pscustomobject]$currentBinding }
            $currentBinding = @{ IpPort = $Matches[1].Trim(); BindingKey = 'hostnameport'; CertHash = $null; AppId = $null }
        }
        elseif ($line -match 'Certificate Hash\s*:\s*(.+)') { $currentBinding.CertHash = $Matches[1].Trim() }
        elseif ($line -match 'Application ID\s*:\s*(.+)') { $currentBinding.AppId = $Matches[1].Trim() }
    }
    if ($currentBinding.Count -gt 0) { $bindingInfo += [pscustomobject]$currentBinding }
    return @($bindingInfo)
}

function Get-NetshBindingForCertificate {
    # All netsh sslcert bindings whose cert hash matches $Thumbprint -> @{ Bindings; AppId }, or $null.
    param([string] $Thumbprint)
    if ([string]::IsNullOrWhiteSpace($Thumbprint)) { return $null }
    try {
        $normalized = ($Thumbprint -replace '[\s:]', '').ToUpper()
        $matching = @(Get-NetshSslBindings | Where-Object {
            $_.CertHash -and ((($_.CertHash -replace '[\s:]', '').ToUpper()) -eq $normalized)
        })
        if ($matching.Count -gt 0) { return @{ Bindings = $matching; AppId = ($matching | Select-Object -First 1).AppId } }
        return $null
    }
    catch {
        Write-Log "Error scanning netsh bindings: $($_.Exception.Message)" -Level WARNING
        return $null
    }
}

function Get-ExistingNetshBindingsForDomain {
    # Netsh bindings currently serving $Domain (via the newest store cert covering it).
    param([string] $Domain)
    try {
        $cert = Get-StoreCertificateForDomain -Domain $Domain
        if (-not $cert) { Write-Log "  No existing certificate in store for $Domain" -Level DEBUG; return $null }
        $result = Get-NetshBindingForCertificate -Thumbprint $cert.Thumbprint
        if ($result) {
            Write-Log "  Found $($result.Bindings.Count) existing netsh binding(s): $(($result.Bindings | ForEach-Object { $_.IpPort }) -join ', ')" -Level INFO
        }
        return $result
    }
    catch {
        Write-Log "Error scanning for existing netsh bindings: $($_.Exception.Message)" -Level WARNING
        return $null
    }
}

function Update-NetshBinding {
    # Rebind one netsh sslcert entry to $Thumbprint (delete + add + verify). $AppId includes braces.
    param([string] $IpPort, [string] $BindingKey, [string] $AppId, [Parameter(Mandatory)][string] $Thumbprint)
    if ([string]::IsNullOrWhiteSpace($IpPort)) {
        Write-Log '    Skipping netsh binding with empty address (could not be parsed from netsh output).' -Level WARNING
        return $false
    }
    if (-not $BindingKey) { $BindingKey = 'ipport' }
    if ($DryRun) { Write-Log "[DryRun] WOULD rebind netsh $BindingKey=$IpPort -> $Thumbprint" -Level INFO; return $true }
    netsh http delete sslcert "$BindingKey=$IpPort" 2>&1 | Out-Null
    if ($BindingKey -eq 'hostnameport') {
        $addResult = netsh http add sslcert hostnameport=$IpPort certhash=$Thumbprint appid="$AppId" certstorename=MY 2>&1
    }
    else {
        $addResult = netsh http add sslcert ipport=$IpPort certhash=$Thumbprint appid="$AppId" 2>&1
    }
    $verify = netsh http show sslcert "$BindingKey=$IpPort" 2>&1
    if ($verify -match $Thumbprint) {
        Write-Log "    Netsh $IpPort -> new thumbprint (verified)" -Level SUCCESS
        return $true
    }
    Write-Log "    Netsh rebind verification failed for ${IpPort}: $addResult" -Level WARNING
    return $false
}

function Update-IISWebBinding {
    param([string] $SiteName, [string] $BindingInformation, [Parameter(Mandatory)][string] $Thumbprint)
    if ($DryRun) { Write-Log "[DryRun] WOULD rebind IIS Web $SiteName [$BindingInformation] -> $Thumbprint" -Level INFO; return $true }
    try {
        $site = Get-Item "IIS:\Sites\$SiteName" -ErrorAction Stop
        $httpsBinding = $site.bindings.collection | Where-Object {
            $_.protocol -eq 'https' -and $_.bindingInformation -eq $BindingInformation
        } | Select-Object -First 1
        if ($httpsBinding) {
            $httpsBinding.AddSslCertificate($Thumbprint, 'my')
            Write-Log "    IIS Web $SiteName [$BindingInformation] -> new thumbprint" -Level SUCCESS
            return $true
        }
        Write-Log "    IIS Web binding $SiteName [$BindingInformation] no longer exists." -Level WARNING
        return $false
    }
    catch {
        Write-Log "    IIS Web rebind failed for ${SiteName}: $($_.Exception.Message)" -Level WARNING
        return $false
    }
}

function Update-IISFTPBinding {
    param([string] $SiteName, [Parameter(Mandatory)][string] $Thumbprint)
    if ($DryRun) { Write-Log "[DryRun] WOULD rebind IIS FTP $SiteName -> $Thumbprint" -Level INFO; return $true }
    try {
        Set-ItemProperty -Path "IIS:\Sites\$SiteName" -Name ftpServer.security.ssl.serverCertHash -Value $Thumbprint -ErrorAction Stop
        Write-Log "    IIS FTP $SiteName -> new thumbprint" -Level SUCCESS
        return $true
    }
    catch {
        Write-Log "    IIS FTP rebind failed for ${SiteName}: $($_.Exception.Message)" -Level WARNING
        return $false
    }
}

function Deploy-Certificate {
    # Fallback deploy when no live bindings were detected: apply the renewed cert per the
    # configured Type (IIS Web / IIS FTP / CertStore / Netsh). Returns $true when bindings were
    # applied (or none are required).
    param([Parameter(Mandatory)][object] $DomainConfig, [Parameter(Mandatory)][object] $NewCert)

    try {
        if ([string]::IsNullOrWhiteSpace($DomainConfig.Type)) {
            Write-Log 'Domain configuration missing Type property. Cannot update bindings.' -Level WARNING
            return $false
        }
        switch ($DomainConfig.Type) {
            'IIS Web' {
                Write-Log 'Updating IIS Web binding...' -Level INFO
                # Search for IIS sites using ANY domain in the certificate (primary + SANs)
                $allCertDomains = @($DomainConfig.MainDomain)
                if ($DomainConfig.SANs) { $allCertDomains += @($DomainConfig.SANs | Where-Object { $_ }) }

                $sitesFound = @()
                $bindingsUpdated = 0
                foreach ($certDomain in $allCertDomains) {
                    Write-Log "  Checking for bindings with domain: $certDomain" -Level DEBUG
                    $sites = Get-ChildItem -Path IIS:\Sites | Where-Object {
                        $_.bindings.collection.bindingInformation -like "*$certDomain*"
                    }
                    foreach ($site in $sites) {
                        if ($sitesFound -notcontains $site.Name) { $sitesFound += $site.Name }
                        $bindings = $site.bindings.collection | Where-Object {
                            $_.protocol -eq 'https' -and $_.bindingInformation -like "*$certDomain*"
                        }
                        foreach ($binding in $bindings) {
                            if (Update-IISWebBinding -SiteName $site.Name -BindingInformation $binding.bindingInformation -Thumbprint $NewCert.Thumbprint) {
                                $bindingsUpdated++
                            }
                        }
                    }
                }
                if ($bindingsUpdated -gt 0) {
                    Write-Log "IIS Web binding(s) updated ($bindingsUpdated binding(s) on $($sitesFound.Count) site(s))." -Level SUCCESS
                    return $true
                }
                Write-Log "No HTTPS bindings found for any domain in certificate: $($allCertDomains -join ', ')" -Level WARNING
                return $false
            }
            'IIS FTP' {
                Write-Log 'Updating IIS FTP binding...' -Level INFO
                $ftpSiteName = if ($DomainConfig.Guid) { $DomainConfig.Guid } else { 'Default FTP Site' }
                if (-not (Test-Path "IIS:\Sites\$ftpSiteName")) {
                    Write-Log "FTP site '$ftpSiteName' not found." -Level WARNING
                    return $false
                }
                return (Update-IISFTPBinding -SiteName $ftpSiteName -Thumbprint $NewCert.Thumbprint)
            }
            'CertStore' {
                Write-Log 'Certificate renewed and stored in LocalMachine\My. No binding updates required.' -Level INFO
                return $true
            }
            'Netsh' {
                Write-Log 'Updating Netsh HTTP.SYS binding(s)...' -Level INFO
                if ([string]::IsNullOrWhiteSpace($DomainConfig.Guid)) {
                    Write-Log 'Netsh configuration missing GUID. Cannot update binding.' -Level WARNING
                    return $false
                }
                $guid = $DomainConfig.Guid -replace '[{}]', ''
                # Support both legacy (NetshIpPort singular) and current (NetshIpPorts array) formats
                $ipPortArray = @()
                if ($DomainConfig.PSObject.Properties['NetshIpPorts'] -and $DomainConfig.NetshIpPorts) { $ipPortArray = @($DomainConfig.NetshIpPorts) }
                elseif ($DomainConfig.PSObject.Properties['NetshIpPort'] -and $DomainConfig.NetshIpPort) { $ipPortArray = @($DomainConfig.NetshIpPort) }
                else { $ipPortArray = @('0.0.0.0:443') }
                Write-Log "Binding configuration: $($ipPortArray.Count) IP:Port(s) (GUID: $guid)" -Level INFO

                $allOk = $true
                foreach ($ipPort in $ipPortArray) {
                    # An IP host => ipport; a DNS name => hostnameport (SNI)
                    $hostPart = ($ipPort -split ':')[0]
                    $parsedIp = [ref]([System.Net.IPAddress]::None)
                    $bindKey = if ([System.Net.IPAddress]::TryParse($hostPart, $parsedIp)) { 'ipport' } else { 'hostnameport' }
                    if (-not (Update-NetshBinding -IpPort $ipPort -BindingKey $bindKey -AppId "{$guid}" -Thumbprint $NewCert.Thumbprint)) {
                        $allOk = $false
                    }
                }
                if ($allOk) { Write-Log 'All netsh bindings updated.' -Level SUCCESS }
                else { Write-Log 'Some netsh bindings failed to update.' -Level WARNING }
                return $allOk
            }
            default {
                Write-Log "Unknown certificate Type: $($DomainConfig.Type). Cannot update bindings." -Level WARNING
                return $false
            }
        }
    }
    catch {
        Write-Log "Error updating binding: $($_.Exception.Message). Old certificate will NOT be removed for safety." -Level WARNING
        return $false
    }
}

#endregion Helpers copied verbatim --------------------------------------------

#region Creator-only helpers --------------------------------------------------

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

function Invoke-CreatorSelfUpdate {
    # Two-script self-update (spec section3, Decision A). Returns $true ONLY if the creator replaced its
    # OWN file (caller halts + tells the admin to re-run). Renew-Cert.ps1 is installed/updated silently
    # in place. Never throws: failures update the shared circuit-breaker and return $false, exactly like
    # renewal's Invoke-SelfUpdate. Caller is DryRun/SkipSelfUpdate-gated.
    param([object] $Config)

    if (-not $SelfPath) { Write-Log 'Cannot resolve own path ($PSCommandPath empty); skipping self-update.' -Level WARNING; return $false }

    $url = if ($ManifestUrl) { $ManifestUrl } elseif ($Config -and $Config.ManifestUrl) { $Config.ManifestUrl } else { $DefaultManifestUrl }

    if ($Config -and $Config.PinVersion) {
        Write-Log "PinVersion=$($Config.PinVersion) set in cert-config - skipping self-update." -Level INFO
        return $false
    }

    $state = Get-SelfUpdateState
    if ([int]$state.consecutiveFailures -ge 2 -and $state.lastAttemptUtc) {
        # lastAttemptUtc is a UTC ISO string; on PS 5.1 [datetime] casts to LOCAL-kind, so normalize back
        # to UTC or the window is skewed by the UTC offset (the #21 fleet bug).
        $sinceH = ((Get-Date).ToUniversalTime() - ([datetime]$state.lastAttemptUtc).ToUniversalTime()).TotalHours
        if ($sinceH -lt 24) {
            Write-Log ("Self-update circuit-breaker open ({0} consecutive fails, last {1:N1}h ago) - backing off 24h." -f $state.consecutiveFailures, $sinceH) -Level WARNING
            return $false
        }
    }

    try {
        Write-Log "Self-update: fetching manifest $url" -Level INFO
        $manifest = Invoke-WithRetry -OperationName 'manifest fetch' -ScriptBlock { Invoke-RestMethod -Uri $url -TimeoutSec 15 -UseBasicParsing }

        # --- (1) Renewal script: install if absent, upgrade if the manifest is newer. ---
        # Isolated in its own try so a renewal download/verify failure does NOT skip the creator
        # self-update below (the two updates are independent). A persistent renewal failure still
        # trips the shared breaker via $renewalOk at the end.
        $renewalLatest = [string]$manifest.renewal.version
        if (-not $renewalLatest) { throw 'manifest has no renewal.version' }
        $renewalOk = $true
        try {
            $renewalOnDisk = Get-OnDiskScriptVersion -Path $RenewalScript
            $renewalAbsent = -not (Test-Path $RenewalScript)
            $renewalCmp    = if ($renewalOnDisk) { Compare-SemVer $renewalOnDisk $renewalLatest } else { -1 }
            if ($renewalAbsent -or $renewalCmp -lt 0) {
                $fromVer = if ($renewalOnDisk) { $renewalOnDisk } else { '(absent)' }
                if ($DryRun) {
                    Write-Log "[DryRun] WOULD install/upgrade Renew-Cert.ps1 ($fromVer -> $renewalLatest) from $($manifest.renewal.url)" -Level INFO
                }
                else {
                    Write-Log "Installing/updating Renew-Cert.ps1 ($fromVer -> $renewalLatest)..." -Level INFO
                    $thumb = Save-VerifiedDownload -Url $manifest.renewal.url -ExpectedSha256 $manifest.renewal.sha256 -TargetPath $RenewalScript -Label 'Renew-Cert.ps1'
                    Write-Log "Renew-Cert.ps1 now at $renewalLatest (signer $thumb)." -Level SUCCESS
                    Write-EventLogEntry $EID.SelfUpdate Information "Renew-Cert.ps1 installed/updated -> $renewalLatest"
                }
            }
            else {
                Write-Log "Renew-Cert.ps1 up to date (on-disk $renewalOnDisk, manifest $renewalLatest)." -Level SUCCESS
            }
        }
        catch {
            $renewalOk = $false
            Write-Log "Renew-Cert.ps1 install/update failed: $($_.Exception.Message). Continuing to the creator self-update check." -Level ERROR
            Write-EventLogEntry $EID.SelfUpdate Error "Renew-Cert.ps1 install/update failed: $($_.Exception.Message)"
        }

        # --- (2) Creator self: replace + halt for re-run if the manifest is newer. ---
        $creatorLatest = [string]$manifest.creator.version
        if (-not $creatorLatest) { throw 'manifest has no creator.version' }
        if ((Compare-SemVer $ScriptVersion $creatorLatest) -lt 0) {
            if ($DryRun) {
                Write-Log "[DryRun] WOULD upgrade creator $ScriptVersion -> $creatorLatest from $($manifest.creator.url) (then halt for re-run)." -Level INFO
                return $false
            }
            Write-Log "Upgrading creator $ScriptVersion -> $creatorLatest..." -Level INFO
            $thumb = Save-VerifiedDownload -Url $manifest.creator.url -ExpectedSha256 $manifest.creator.sha256 -TargetPath $SelfPath -Label 'Create-New-Cert.ps1'
            Write-Log "Creator upgraded $ScriptVersion -> $creatorLatest (signer $thumb)." -Level SUCCESS
            Write-EventLogEntry $EID.SelfUpdate Information "Creator self-updated $ScriptVersion -> $creatorLatest"
            $state.consecutiveFailures = 0; Save-SelfUpdateState $state
            return $true
        }
        Write-Log "Creator up to date (current $ScriptVersion, manifest $creatorLatest)." -Level SUCCESS

        # Reset the breaker only on a fully-clean pass; a renewal-only failure still counts so repeated
        # failures eventually back off (the renewal-absent case is caught fatally by Main).
        if ($renewalOk) {
            $state.consecutiveFailures = 0
        }
        else {
            $state.consecutiveFailures = [int]$state.consecutiveFailures + 1
            $state.lastAttemptUtc = (Get-Date).ToUniversalTime().ToString('o')
        }
        Save-SelfUpdateState $state
        return $false
    }
    catch {
        $state.consecutiveFailures = [int]$state.consecutiveFailures + 1
        $state.lastAttemptUtc = (Get-Date).ToUniversalTime().ToString('o')
        Save-SelfUpdateState $state
        Write-Log "Self-update failed (attempt $($state.consecutiveFailures)): $($_.Exception.Message). Continuing on current version $ScriptVersion." -Level ERROR
        return $false
    }
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

function Initialize-VaultSecrets {
    # Sync shared secrets from the vault exactly ONCE per run, lazily, on the paths that actually need
    # them (issuance) - so a run that ends in [U]/[D]/[Q] never pays the Azure connect + 4-secret fetch.
    # Spec section4 requires the sync "before issuance"; this is that point. Creator aborts on failure
    # (must not issue stale secrets); under DryRun the read is best-effort (test isolation - the SP cert
    # may be absent on a workstation). Emits the secrets-sync telemetry event (Decision C).
    param([object] $Config)
    if ($script:VaultSecretsSynced) { return }
    $vaultName = Get-ResolvedVaultName -Config $Config
    try {
        $changed = Sync-SecretsFromVault -VaultName $vaultName
        Send-Telemetry -Config $Config -Outcome ([pscustomobject]@{ Action = 'secrets-sync'; RunOutcome = $(if ($changed) { 'Refreshed' } else { 'NoChange' }) })
        $script:VaultSecretsSynced = $true
    }
    catch {
        if ($DryRun) {
            Write-Log "[DryRun] vault sync skipped: $($_.Exception.Message)" -Level WARNING
            $script:VaultSecretsSynced = $true   # don't retry per call under DryRun
            return
        }
        Write-EventLogEntry $EID.Start Error "Vault secrets sync failed: $($_.Exception.Message)"
        throw "Vault secrets sync failed: $($_.Exception.Message). Aborting before any issuance."
    }
}

function Set-ConfigVersionStamps {
    # Single source of truth for the config's script-version stamps (used by both first-run config
    # creation and the Billing save, so a freshly-created config and a billing-updated one agree).
    param([Parameter(Mandatory)][object] $Config)
    $Config | Add-Member -NotePropertyName 'CreatorScriptVersion' -NotePropertyValue $ScriptVersion -Force
    $rv = Get-OnDiskScriptVersion -Path $RenewalScript
    if ($rv) { $Config | Add-Member -NotePropertyName 'RenewalScriptVersion' -NotePropertyValue $rv -Force }
    return $Config
}

function New-DefaultCertConfig {
    # The skeleton config written on first run before any domain is added (spec section3 schema).
    $config = [pscustomobject]@{
        SchemaVersion        = 2
        RenewalScriptVersion = $null
        CreatorScriptVersion = $null
        SharedPoshAcmePath   = $SharedPoshAcmeDefault
        ManifestUrl          = $null
        PinVersion           = $null
        SecretsVault         = $null
        Billing              = $null
        Domains              = @()
    }
    return (Set-ConfigVersionStamps -Config $config)
}

function Read-BillingPrompts {
    # spec section5 - the only interactive credential-ish input. Prompts for the per-install Billing block
    # (plaintext customer identifiers, not secrets) and persists it. Idempotent: a complete existing block
    # is shown and kept unless the admin chooses to update it. Returns the (possibly new) config object.
    param([object] $Config)

    if (-not $Config) { $Config = New-DefaultCertConfig }

    $existing = $Config.Billing
    $complete = $existing -and $existing.Abr -and $existing.CustomerName -and $existing.CustomerNr -and $existing.InvoiceCode
    if ($complete) {
        Write-Log "Billing block present (Customer: $($existing.CustomerName), Nr: $($existing.CustomerNr), Invoice: $($existing.InvoiceCode))." -Level INFO
        if ($DryRun) { return $Config }
        if ((Read-Host 'Update the Billing block? (y/N)').Trim().ToUpper() -ne 'Y') { return $Config }
    }

    Write-Log 'Enter the Billing block (customer identifiers stamped on Teams cards / telemetry):' -Level INFO
    $abr      = (Read-Host 'Abbreviation (Abr)').Trim()
    $custName = (Read-Host 'Customer name').Trim()
    $custNr   = (Read-Host 'Customer number').Trim()
    $invoice  = (Read-Host 'Invoice code').Trim()
    $svcRaw   = Read-Host 'Services (comma-separated) [CertRenewal]'
    $services = if ([string]::IsNullOrWhiteSpace($svcRaw)) { @('CertRenewal') }
                else { @($svcRaw -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }

    $billing = [pscustomobject][ordered]@{
        Abr = $abr; CustomerName = $custName; CustomerNr = $custNr; InvoiceCode = $invoice; Services = $services
    }
    $Config | Add-Member -NotePropertyName 'Billing' -NotePropertyValue $billing -Force
    $null = Set-ConfigVersionStamps -Config $Config
    $null = Save-CertConfig -Config $Config -Reason 'Billing block'
    return $Config
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

function Unregister-RenewalTask {
    # Remove the renewal scheduled task (used by the Delete flow when the last domain is removed). DryRun-gated.
    if ($DryRun) { Write-Log "[DryRun] WOULD unregister scheduled task '$RenewalTaskName'." -Level INFO; return $true }
    try {
        if (Get-ScheduledTask -TaskName $RenewalTaskName -ErrorAction SilentlyContinue) {
            Unregister-ScheduledTask -TaskName $RenewalTaskName -Confirm:$false
            Write-Log "Scheduled task '$RenewalTaskName' unregistered." -Level SUCCESS
        }
        else { Write-Log "Scheduled task '$RenewalTaskName' not present; nothing to remove." -Level INFO }
        return $true
    }
    catch { Write-Log "Failed to unregister scheduled task: $($_.Exception.Message)" -Level WARNING; return $false }
}

function Test-ValidFQDN {
    # Accept a wildcard (*.example.com) or a regular FQDN: at least one dot + valid label characters.
    param([string] $FQDN)
    if ($FQDN -notmatch '^(\*\.)?([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$') { return $false }
    return $true
}

function Test-DnsCnameRecords {
    # Creator-only (not in Renew-Cert.ps1). Verify each domain has its DNS-01 _acme-challenge CNAME
    # pointing at the certval.no delegation, querying internal DNS first then public resolvers.
    # Returns $true only if every domain validates. Read-only (safe under DryRun).
    param(
        [Parameter(Mandatory)][string[]] $Domains,
        [switch] $IsRetry
    )
    $validationFailed = $false
    $actionText = if ($IsRetry) { 'Rechecking' } else { 'Checking' }

    foreach ($checkDomain in $Domains) {
        try {
            $domainSuffix    = Get-DomainSuffix -FQDN $checkDomain
            $validationDomain = "$domainSuffix.certval.no"
            $challengeDomain = Get-AcmeChallengeDomain -Domain $checkDomain
            $challengeTarget = Get-AcmeChallengeDomain -Domain $validationDomain

            Write-Log "$actionText DNS CNAME record for $challengeDomain..." -Level INFO
            $cnameFound = $false
            try {
                $cname = Resolve-DnsName -Name $challengeDomain -Type CNAME -ErrorAction Stop
                Write-Log "  CNAME record found (internal DNS): $($cname.NameHost)" -Level SUCCESS
                $cnameFound = $true
            }
            catch {
                Write-Log '  CNAME record not found via internal DNS, trying external DNS servers...' -Level WARNING
                foreach ($dnsServer in @('8.8.8.8', '1.1.1.1')) {
                    try {
                        $cname = Resolve-DnsName -Name $challengeDomain -Type CNAME -Server $dnsServer -ErrorAction Stop
                        Write-Log "  CNAME record found (external DNS via $dnsServer): $($cname.NameHost)" -Level SUCCESS
                        $cnameFound = $true
                        break
                    }
                    catch { }   # try the next resolver
                }
            }

            if (-not $cnameFound) {
                $notFoundText = if ($IsRetry) { 'still not found' } else { 'not found' }
                Write-Log "  CNAME record $notFoundText on any DNS server!" -Level ERROR
                if (-not $IsRetry) {
                    Write-Log "  Please create a CNAME record:  Name: $challengeDomain  Type: CNAME  Value: $challengeTarget" -Level WARNING
                    if ($checkDomain -match '^\*\.') { Write-Log "  Note: for wildcard domain $checkDomain" -Level INFO }
                }
                $validationFailed = $true
            }
        }
        catch {
            Write-Log "  Error processing domain ${checkDomain}: $($_.Exception.Message)" -Level ERROR
            $validationFailed = $true
        }
    }
    return (-not $validationFailed)
}

function Test-CaaRecordForLetsEncrypt {
    # Creator-only (not in Renew-Cert.ps1). Walk the domain tree (RFC 8659) and confirm any CAA
    # records permit Let's Encrypt issuance. Uses DnsClient-PS (Resolve-Dns). On a DNS error it
    # returns Success (do not block issuance on a transient lookup failure). Read-only.
    param(
        [Parameter(Mandatory)][string] $Domain,
        [switch] $IsWildcard
    )
    $checkDomain = $Domain
    if ($Domain -match '^\*\.(.+)$') { $checkDomain = $Matches[1]; $IsWildcard = $true }

    Write-Log "Checking CAA records for $checkDomain (walking up domain tree)..." -Level INFO
    try {
        $currentDomain = $checkDomain
        $caaRecords = $null
        $caaFoundAt = $null
        while ($currentDomain -match '\.') {
            Write-Log "  Querying CAA at $currentDomain..." -Level DEBUG
            $caaResult = Resolve-Dns -Query $currentDomain -QueryType CAA -ErrorAction SilentlyContinue
            if ($caaResult.Answers -and $caaResult.Answers.Count -gt 0) {
                $caaRecords = $caaResult.Answers
                $caaFoundAt = $currentDomain
                break
            }
            $dotIndex = $currentDomain.IndexOf('.')
            if ($dotIndex -lt 0 -or $dotIndex -ge ($currentDomain.Length - 1)) { break }
            $currentDomain = $currentDomain.Substring($dotIndex + 1)
        }

        if (-not $caaRecords -or $caaRecords.Count -eq 0) {
            Write-Log '  No CAA records found in domain hierarchy - certificate issuance allowed.' -Level SUCCESS
            return @{ Success = $true; Message = 'No CAA restrictions' }
        }
        Write-Log "  Found $($caaRecords.Count) CAA record(s) at $caaFoundAt" -Level INFO

        $hasIssue = $false; $hasIssuewild = $false; $letsEncryptIssue = $false; $letsEncryptIssuewild = $false
        foreach ($record in $caaRecords) {
            $tag = $null; $value = $null; $recordDataStr = $null
            try {
                if ($record.RecordData -and $record.RecordData.PSObject.Properties['Tag']) {
                    $tag = $record.RecordData.Tag
                    $value = $record.RecordData.Value
                    $recordDataStr = "$($record.RecordData.Flags) $tag `"$value`""
                }
                elseif ($record.RecordData) { $recordDataStr = $record.RecordData.ToString() }
                else { $recordDataStr = $record.ToString() }
            }
            catch { $recordDataStr = "$record" }
            Write-Log "    $recordDataStr" -Level DEBUG

            if ($tag) {
                if ($tag -eq 'issue') { $hasIssue = $true; if ($value -match 'letsencrypt\.org') { $letsEncryptIssue = $true } }
                elseif ($tag -eq 'issuewild') { $hasIssuewild = $true; if ($value -match 'letsencrypt\.org') { $letsEncryptIssuewild = $true } }
            }
            elseif ($recordDataStr) {
                if ($recordDataStr -match '\bissue\s+"([^"]+)"') { $hasIssue = $true; if ($Matches[1] -match 'letsencrypt\.org') { $letsEncryptIssue = $true } }
                if ($recordDataStr -match '\bissuewild\s+"([^"]+)"') { $hasIssuewild = $true; if ($Matches[1] -match 'letsencrypt\.org') { $letsEncryptIssuewild = $true } }
            }
        }

        if ($IsWildcard) {
            if ($hasIssuewild) {
                if ($letsEncryptIssuewild) {
                    Write-Log "  CAA allows Let's Encrypt wildcard certificates (issuewild)." -Level SUCCESS
                    return @{ Success = $true; Message = "Let's Encrypt authorized for wildcards" }
                }
                return @{ Success = $false; Message = "CAA 'issuewild' records at $caaFoundAt exist but letsencrypt.org is not listed"; RequiredAction = "Add CAA record: $caaFoundAt. CAA 0 issuewild `"letsencrypt.org`"" }
            }
            elseif ($hasIssue) {
                if ($letsEncryptIssue) {
                    Write-Log "  CAA allows Let's Encrypt certificates (issue, no issuewild restrictions)." -Level SUCCESS
                    return @{ Success = $true; Message = "Let's Encrypt authorized via issue" }
                }
                return @{ Success = $false; Message = "CAA 'issue' records at $caaFoundAt exist but letsencrypt.org is not listed"; RequiredAction = "Add CAA records at ${caaFoundAt}: `n  $caaFoundAt. CAA 0 issue `"letsencrypt.org`"`n  $caaFoundAt. CAA 0 issuewild `"letsencrypt.org`"" }
            }
        }
        else {
            if ($hasIssue) {
                if ($letsEncryptIssue) {
                    Write-Log "  CAA allows Let's Encrypt certificates (issue)." -Level SUCCESS
                    return @{ Success = $true; Message = "Let's Encrypt authorized" }
                }
                return @{ Success = $false; Message = "CAA 'issue' records at $caaFoundAt exist but letsencrypt.org is not listed"; RequiredAction = "Add CAA record: $caaFoundAt. CAA 0 issue `"letsencrypt.org`"" }
            }
        }

        Write-Log '  CAA records present but do not restrict Let''s Encrypt.' -Level SUCCESS
        return @{ Success = $true; Message = "No Let's Encrypt restrictions in CAA" }
    }
    catch {
        Write-Log "  Error querying CAA records: $($_.Exception.Message). Proceeding without CAA validation." -Level WARNING
        return @{ Success = $true; Message = 'CAA check skipped due to DNS error' }
    }
}

function Initialize-PoshAcme {
    # Prepare the shared Posh-ACME store the SYSTEM renewal task also reads: ensure the modules are
    # present (hard error if not - same discipline as Connect-SecretsVault, no auto-install), create
    # the shared dir with a SYSTEM FullControl ACL, point POSHACME_HOME at it, and import Posh-ACME.
    # Returns the resolved shared path. DryRun-gated for the dir/ACL creation.
    param([object] $Config)
    foreach ($m in 'Posh-ACME', 'DnsClient-PS') {
        if (-not (Get-Module -ListAvailable -Name $m)) { throw "Required module '$m' is not installed (Install-Module $m)." }
    }
    $sharedPath = if ($Config -and $Config.SharedPoshAcmePath) { [string]$Config.SharedPoshAcmePath } else { $SharedPoshAcmeDefault }

    if (-not (Test-Path $sharedPath)) {
        if ($DryRun) { Write-Log "[DryRun] WOULD create shared Posh-ACME directory $sharedPath." -Level INFO }
        else { New-Item -ItemType Directory -Path $sharedPath -Force | Out-Null; Write-Log "Created shared Posh-ACME directory $sharedPath." -Level INFO }
    }
    # SYSTEM needs FullControl so the daily renewal task (runs as SYSTEM) can read the account + order state.
    if (-not $DryRun -and (Test-Path $sharedPath)) {
        try {
            $acl = Get-Acl $sharedPath
            $systemSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')   # NT AUTHORITY\SYSTEM
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                $systemSid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
            $acl.SetAccessRule($rule)
            Set-Acl -Path $sharedPath -AclObject $acl
            Write-Log "  Granted SYSTEM FullControl on $sharedPath (shared Posh-ACME store)." -Level DEBUG
        }
        catch { Write-Log "Could not set SYSTEM ACL on ${sharedPath}: $($_.Exception.Message)" -Level WARNING }
    }

    $env:POSHACME_HOME = $sharedPath
    Write-Log "POSHACME_HOME set to $sharedPath." -Level INFO
    Import-Module Posh-ACME -Force -ErrorAction Stop
    # Best-effort: load the IIS:\ provider so Deploy-Certificate can rebind IIS Web/FTP sites at creation.
    if (Get-Module -ListAvailable -Name WebAdministration) { Import-Module WebAdministration -ErrorAction SilentlyContinue }
    return $sharedPath
}

function Set-AcmeAccount {
    # Posh-ACME account setup (ported from v1 ~1219-1356). Selects the configured ACME server
    # (cert-config.AcmeServer, default LE_PROD), then reuses cert-config.PaAccount if it still exists,
    # else any existing account, else creates one with -UseAltPluginEncryption (required so the SYSTEM
    # renewal can decrypt the per-order plugin args). Returns the active account id. DryRun-gates account
    # creation. New-PAAccount uses $Email as the ACME contact.
    param([object] $Config, [string] $Email)

    $acmeServer = if ($Config -and $Config.AcmeServer) { [string]$Config.AcmeServer } else { 'LE_PROD' }
    Write-Log "ACME server: $acmeServer" -Level INFO
    Set-PAServer $acmeServer

    $newAccountScript = {
        if ($DryRun) { Write-Log '[DryRun] WOULD create a new ACME account (-UseAltPluginEncryption).' -Level INFO; return '(dry-run-account)' }
        New-PAAccount -Contact $Email -AcceptTOS -UseAltPluginEncryption | Out-Null
        $id = (Get-PAAccount).id
        Write-Log "New ACME account created: $id" -Level SUCCESS
        return $id
    }

    $configuredId = if ($Config) { $Config.PaAccount } else { $null }
    if ($configuredId) {
        $existing = Get-PAAccount -ID $configuredId -ErrorAction SilentlyContinue
        if ($existing) {
            Set-PAAccount -ID $configuredId
            if ([string]::IsNullOrEmpty($existing.sskey)) {
                Write-Log 'Configured account does not use alternate plugin encryption - SYSTEM renewals may fail to decrypt plugin credentials.' -Level WARNING
            }
            else { Write-Log 'Alternate plugin encryption: enabled.' -Level SUCCESS }
            Write-Log "Using existing ACME account: $configuredId" -Level INFO
            return $configuredId
        }
        Write-Log "Account id $configuredId from config not found in Posh-ACME; checking for any existing account..." -Level WARNING
    }

    $any = Get-PAAccount
    if (-not $any) {
        Write-Log 'No existing ACME account found. Creating one...' -Level INFO
        return (& $newAccountScript)
    }

    Set-PAAccount -ID $any.id
    $details = Get-PAAccount -ID $any.id
    if ([string]::IsNullOrEmpty($details.sskey)) {
        Write-Log 'Existing account does not use alternate plugin encryption (required for SYSTEM renewals).' -Level WARNING
        $choice = $null
        do {
            $choice = (Read-Host 'Create a NEW account with correct encryption? ([C]reate / [K]eep existing / [Q]uit)').Trim().ToUpper()
            switch ($choice) {
                'C' { return (& $newAccountScript) }
                'K' { Write-Log 'Keeping existing account - SYSTEM renewals may fail.' -Level WARNING; return $any.id }
                'Q' { throw 'ACME account setup aborted by administrator.' }
                default { Write-Log 'Invalid choice. Enter C, K, or Q.' -Level WARNING; $choice = $null }
            }
        } while ($null -eq $choice)
    }
    Write-Log "Using existing ACME account: $($any.id) (alternate plugin encryption enabled)." -Level SUCCESS
    return $any.id
}

function Invoke-DomainValidation {
    # DNS-01 CNAME + CAA validation for one cert's full domain set, with the v1 retry/skip/abort
    # prompts. Returns 'Validated' | 'Skip' | 'Abort'. Read-only (safe under DryRun).
    param([Parameter(Mandatory)][string] $MainDomain, [Parameter(Mandatory)][string[]] $AllDomains)

    $dnsOk = Test-DnsCnameRecords -Domains $AllDomains
    if (-not $dnsOk) {
        Write-Log "DNS validation failed for $MainDomain." -Level ERROR
        while ($true) {
            $choice = (Read-Host 'DNS validation: [R]etry (after fixing CNAMEs) / [S]kip this cert / [A]bort').Trim().ToUpper()
            if ($choice -eq 'R') { if (Test-DnsCnameRecords -Domains $AllDomains -IsRetry) { break } else { Write-Log 'DNS validation still failing.' -Level ERROR; continue } }
            elseif ($choice -eq 'S') { return 'Skip' }
            elseif ($choice -eq 'A') { return 'Abort' }
            else { Write-Log 'Invalid choice. Enter R, S, or A.' -Level WARNING }
        }
    }

    $isWildcard = $MainDomain -match '^\*\.'
    $caa = Test-CaaRecordForLetsEncrypt -Domain $MainDomain -IsWildcard:$isWildcard
    if (-not $caa.Success) {
        Write-Log "CAA validation failed for ${MainDomain}: $($caa.Message)" -Level ERROR
        if ($caa.RequiredAction) { Write-Log "  Required action: $($caa.RequiredAction)" -Level WARNING }
        while ($true) {
            $choice = (Read-Host 'CAA validation: [R]etry (after adding CAA) / [S]kip this cert / [A]bort').Trim().ToUpper()
            if ($choice -eq 'R') {
                $caa = Test-CaaRecordForLetsEncrypt -Domain $MainDomain -IsWildcard:$isWildcard
                if ($caa.Success) { break } else { Write-Log "CAA validation still failing: $($caa.Message)" -Level ERROR; continue }
            }
            elseif ($choice -eq 'S') { return 'Skip' }
            elseif ($choice -eq 'A') { return 'Abort' }
            else { Write-Log 'Invalid choice. Enter R, S, or A.' -Level WARNING }
        }
    }
    return 'Validated'
}

function New-Certificate {
    # Issue + install + deploy ONE certificate (ported from v1 issuance ~1482-1605). Domain validation
    # is done by the caller. Returns the installed certificate object, or $null under DryRun. Throws on
    # a hard issuance/install failure (the caller records it as failed and continues). Domeneshop creds
    # come from the synced cert-secrets.json (Decision D); DnsAlias points every domain at certval.no.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '',
        Justification = 'Domeneshop secret is DPAPI-LM encrypted at rest (cert-secrets.json); the Posh-ACME plugin requires a SecureString at runtime.')]
    param(
        [Parameter(Mandatory)][object] $DomainConfig,
        [Parameter(Mandatory)][string[]] $AllDomains,
        [Parameter(Mandatory)][object] $Secrets
    )

    $mainDomain = $DomainConfig.MainDomain
    $dnsAliasArray = @()
    foreach ($d in $AllDomains) {
        $suffix = Get-DomainSuffix -FQDN $d
        $dnsAliasArray += Get-AcmeChallengeDomain -Domain "$suffix.certval.no"
    }
    Write-Log "Requesting certificate for $mainDomain (domains: $($AllDomains -join ', '))" -Level INFO
    Write-Log "  DnsAlias: $($dnsAliasArray -join ', ')" -Level DEBUG

    if ($DryRun) {
        Write-Log "[DryRun] WOULD issue (New-PACertificate), install to LocalMachine\My, and deploy bindings (Type=$($DomainConfig.Type)) for $mainDomain." -Level INFO
        return $null
    }

    $pluginArgs = @{
        DomeneshopToken  = $Secrets.DomeneshopToken
        DomeneshopSecret = (ConvertTo-SecureString -String $Secrets.DomeneshopSecret -AsPlainText -Force)
    }
    # No -Contact here: the account is already selected by Set-AcmeAccount (passing it can create a new one).
    $poshParams = @{
        Domain     = $AllDomains
        Plugin     = 'Domeneshop'
        PluginArgs = $pluginArgs
        DnsAlias   = $dnsAliasArray
        AcceptTOS  = $true
        Force      = $true
    }
    $cert = Invoke-WithRetry -OperationName "Certificate request for $mainDomain" -MaxRetries 3 -InitialDelaySeconds 10 -ScriptBlock {
        New-PACertificate @poshParams
    }
    Write-Log "Certificate issued: subject=$($cert.Subject) thumbprint=$($cert.Thumbprint) expires=$($cert.NotAfter)" -Level SUCCESS

    Install-PACertificate -PACertificate $cert -StoreLocation LocalMachine -StoreName My
    Write-Log '  Installed to LocalMachine\My.' -Level SUCCESS

    # Deploy per the configured Type via the shared renewal family (handles netsh / IIS Web / IIS FTP / store).
    $deployConfig = [pscustomobject]@{
        MainDomain   = $mainDomain
        Type         = $DomainConfig.Type
        Guid         = $DomainConfig.Guid
        SANs         = $DomainConfig.SANs
        NetshIpPorts = $DomainConfig.NetshIpPorts
    }
    $null = Deploy-Certificate -DomainConfig $deployConfig -NewCert $cert
    Write-Log "Deployment completed for $mainDomain." -Level SUCCESS
    return $cert
}

#endregion Creator-only helpers -----------------------------------------------

#region Interactive menu ------------------------------------------------------

function Read-NetshBinding {
    # Interactive netsh IP:port capture for a Netsh-type domain (ported from v1 ~937-1109): offer to
    # reuse the domain's existing bindings, else collect IP:port(s) manually with conflict detection
    # against $KnownBindings (ipPort -> domain already configured this run / in config). Returns
    # @{ Guid; NetshIpPorts }.
    param([Parameter(Mandatory)][string] $FQDN, [hashtable] $KnownBindings = @{})

    $ipPortArray = @()
    $guid = $null

    Write-Log "Checking for existing netsh bindings for $FQDN..." -Level INFO
    $existing = Get-ExistingNetshBindingsForDomain -Domain $FQDN
    if ($existing -and $existing.Bindings.Count -gt 0) {
        $bindingChoice = $null
        do {
            $bindingChoice = (Read-Host 'Existing bindings detected - [U]se existing (recommended) / [M]anually configure').Trim().ToUpper()
            if ($bindingChoice -eq 'U') {
                foreach ($b in $existing.Bindings) { $ipPortArray += $b.IpPort }
                if ($existing.AppId) {
                    $guid = $existing.AppId -replace '[{}]', ''
                    try { [System.Guid]::Parse($guid) | Out-Null }
                    catch { Write-Log 'Invalid GUID on existing binding - generating a new one.' -Level WARNING; $guid = [guid]::NewGuid().ToString() }
                }
                else { $guid = [guid]::NewGuid().ToString() }
                Write-Log "Using existing binding configuration: $($ipPortArray -join ', ') (AppId GUID: $guid)" -Level INFO
            }
            elseif ($bindingChoice -eq 'M') { }   # fall through to manual capture
            else { Write-Log 'Invalid choice. Enter U or M.' -Level WARNING; $bindingChoice = $null }
        } while ($null -eq $bindingChoice)
    }

    if ($ipPortArray.Count -eq 0) {
        Write-Log 'Configuring netsh bindings manually (one or more IP:port).' -Level INFO
        while ($true) {
            $ipAddress = Read-Host 'IP address to bind (default 0.0.0.0, or Enter to finish once at least one is added)'
            if ([string]::IsNullOrWhiteSpace($ipAddress) -and $ipPortArray.Count -gt 0) { break }
            if ([string]::IsNullOrWhiteSpace($ipAddress)) { $ipAddress = '0.0.0.0' }

            $port = Read-Host 'Port to bind (default 443)'
            if ([string]::IsNullOrWhiteSpace($port)) { $port = '443' }
            else {
                $portNum = 0
                if (-not [int]::TryParse($port, [ref]$portNum) -or $portNum -lt 1 -or $portNum -gt 65535) {
                    Write-Log 'Invalid port. Must be 1-65535.' -Level WARNING; continue
                }
            }
            $ipPort = "${ipAddress}:${port}"
            if ($ipPortArray -contains $ipPort) { Write-Log "Binding $ipPort already added. Skipping." -Level WARNING; continue }

            if ($KnownBindings.ContainsKey($ipPort)) {
                Write-Log "BINDING CONFLICT: $ipPort is already used by $($KnownBindings[$ipPort]). Only one certificate can bind it; proceeding will replace that binding." -Level WARNING
                if ((Read-Host 'Proceed and replace the existing binding? (Y/N)').Trim().ToUpper() -ne 'Y') { Write-Log 'Skipping this binding.' -Level INFO; continue }
            }

            $ipPortArray += $ipPort
            Write-Log "Added binding: $ipPort" -Level SUCCESS
            if ((Read-Host 'Add another IP:port binding? (Y/N)').Trim().ToUpper() -ne 'Y') { break }
        }
        if (-not $guid) { $guid = [guid]::NewGuid().ToString() }
    }

    return @{ Guid = $guid; NetshIpPorts = $ipPortArray }
}

function Read-DomainsToAdd {
    # Interactive collection of the new certificates to issue (ported from v1 ~856-1153). For each
    # primary FQDN: validate format, optionally collect SANs, pick a deployment Type (IIS Web / IIS FTP
    # / CertStore / Netsh), and an optional post-renewal service restart. Returns an array of domain
    # config objects ([pscustomobject] MainDomain/Type/Guid/SANs/NetshIpPorts/RestartService).
    param([object[]] $ExistingDomains = @())

    $existingNames = @{}
    $knownNetsh = @{}    # ipPort -> domain, for conflict detection
    foreach ($d in $ExistingDomains) {
        if ($d.MainDomain) { $existingNames[[string]$d.MainDomain] = $d }
        if ($d.Type -eq 'Netsh' -and $d.NetshIpPorts) { foreach ($p in @($d.NetshIpPorts)) { $knownNetsh[[string]$p] = [string]$d.MainDomain } }
    }

    $collected = @()
    while ($true) {
        $fqdn = (Read-Host 'Enter primary FQDN (or press Enter to finish)').Trim()
        if ($fqdn -eq '') { break }
        if (-not (Test-ValidFQDN -FQDN $fqdn)) {
            Write-Log "Invalid FQDN format: $fqdn (expected sub.domain.tld or *.domain.tld)." -Level WARNING
            continue
        }
        if ($existingNames.ContainsKey($fqdn) -or @($collected | Where-Object { $_.MainDomain -eq $fqdn }).Count -gt 0) {
            if ((Read-Host "$fqdn is already configured. Reconfigure it? (Y/N)").Trim().ToUpper() -ne 'Y') { Write-Log "Keeping existing configuration for $fqdn." -Level INFO; continue }
            $collected = @($collected | Where-Object { $_.MainDomain -ne $fqdn })
        }

        # SANs
        $sans = @()
        if ((Read-Host 'Add Subject Alternative Names (SANs) to this certificate? (Y/N)').Trim().ToUpper() -eq 'Y') {
            while ($true) {
                $san = (Read-Host 'Enter SAN domain (or press Enter to finish)').Trim()
                if ($san -eq '') { break }
                if (-not (Test-ValidFQDN -FQDN $san)) { Write-Log "Invalid FQDN format: $san." -Level WARNING; continue }
                if ($san -eq $fqdn) { Write-Log 'That is the primary domain. Skipping.' -Level WARNING }
                elseif ($sans -contains $san) { Write-Log 'SAN already added. Skipping.' -Level WARNING }
                else { $sans += $san; Write-Log "Added SAN: $san" -Level SUCCESS }
            }
        }

        # Deployment Type
        $type = $null; $guid = $null; $netshIpPorts = $null
        $validType = $false
        do {
            $envChoice = (Read-Host 'Deployment type - [W] IIS Web / [F] IIS FTP / [C] CertStore only / [N] Netsh HTTP.SYS').Trim().ToUpper()
            switch ($envChoice) {
                'W' { $type = 'IIS Web'; $validType = $true }
                'C' { $type = 'CertStore'; $validType = $true }
                'F' {
                    $ftpSite = (Read-Host 'FTP site name (default: Default FTP Site)').Trim()
                    if ([string]::IsNullOrWhiteSpace($ftpSite)) { $ftpSite = 'Default FTP Site' }
                    $type = 'IIS FTP'; $guid = $ftpSite; $validType = $true
                }
                'N' {
                    $netsh = Read-NetshBinding -FQDN $fqdn -KnownBindings $knownNetsh
                    if (@($netsh.NetshIpPorts).Count -eq 0) { Write-Log 'At least one IP:port is required for Netsh. Choose a type again.' -Level WARNING; $validType = $false }
                    else {
                        $type = 'Netsh'; $guid = $netsh.Guid; $netshIpPorts = @($netsh.NetshIpPorts)
                        foreach ($p in $netshIpPorts) { $knownNetsh[[string]$p] = $fqdn }
                        $validType = $true
                    }
                }
                default { Write-Log 'Invalid choice. Enter W, F, C, or N.' -Level WARNING; $validType = $false }
            }
        } while (-not $validType)

        # Optional post-renewal service restart
        $restartService = $null
        if ((Read-Host 'Restart a Windows service after successful renewal? (Y/N)').Trim().ToUpper() -eq 'Y') {
            $svcName = (Read-Host 'Windows service name to restart').Trim()
            if (-not [string]::IsNullOrWhiteSpace($svcName)) {
                $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
                if ($svc) { Write-Log "Service found: $($svc.DisplayName) (Status: $($svc.Status))." -Level SUCCESS; $restartService = $svcName }
                elseif ((Read-Host "Service '$svcName' not found on this machine. Configure it anyway? (Y/N)").Trim().ToUpper() -eq 'Y') { $restartService = $svcName }
            }
        }

        $collected += [pscustomobject]@{
            MainDomain     = $fqdn
            Type           = $type
            Guid           = $guid
            SANs           = $sans
            NetshIpPorts   = $netshIpPorts
            RestartService = $restartService
        }
        $sanStr = if ($sans.Count -gt 0) { " + SANs: $($sans -join ', ')" } else { '' }
        Write-Log "Queued: $fqdn [$type]$sanStr" -Level INFO
    }
    return $collected
}

function ConvertTo-DomainConfigObject {
    # Build the cert-config.json Domains[] entry for an issued domain (matches the schema Renew-Cert.ps1
    # consumes: MainDomain/Type/Guid/SANs/Thumbprint/NotAfter + optional NetshIpPorts/RestartService).
    param([Parameter(Mandatory)][object] $DomainConfig, [object] $Cert)
    $cleanSans = @(); if ($DomainConfig.SANs) { $cleanSans = @($DomainConfig.SANs | Where-Object { $_ }) }
    $obj = [pscustomobject]@{
        MainDomain = $DomainConfig.MainDomain
        Type       = $DomainConfig.Type
        Guid       = $DomainConfig.Guid
        SANs       = $cleanSans
        Thumbprint = if ($Cert) { $Cert.Thumbprint } else { $null }
        NotAfter   = if ($Cert) { ([datetime]$Cert.NotAfter).ToString('yyyy-MM-dd HH:mm:ss') } else { $null }
    }
    if ($DomainConfig.NetshIpPorts -and @($DomainConfig.NetshIpPorts).Count -gt 0) {
        $obj | Add-Member -NotePropertyName 'NetshIpPorts' -NotePropertyValue (@($DomainConfig.NetshIpPorts | Where-Object { $_ }))
    }
    if ($DomainConfig.RestartService) { $obj | Add-Member -NotePropertyName 'RestartService' -NotePropertyValue $DomainConfig.RestartService }
    return $obj
}

function Invoke-AddFlow {
    # spec section6 Add: collect domains, sync the shared secrets (Decision D), set up Posh-ACME + the
    # ACME account, validate DNS-01/CAA and issue each cert (New-Certificate), then merge the successes
    # into cert-config.json (incl. PaAccount) and register the daily renewal task. Per-domain failures
    # are reported and skipped; an admin [A]bort during validation stops the run with nothing saved.
    param([object] $Config)

    $existingDomains = @(); if ($Config -and $Config.Domains) { $existingDomains = @($Config.Domains) }
    $toAdd = @(Read-DomainsToAdd -ExistingDomains $existingDomains)
    if ($toAdd.Count -eq 0) { Write-Log 'No new domains entered - nothing to add.' -Level INFO; return }

    # Fresh shared secrets, then Posh-ACME / account setup (all before any issuance, spec section4).
    Initialize-VaultSecrets -Config $Config
    $secrets = if (Test-Path $SecretsPath) { Get-Secrets }
               elseif ($DryRun) { [pscustomobject]@{ DomeneshopToken = '(dry-run)'; DomeneshopSecret = '(dry-run)'; TeamsWebhookUrl = $null; Email = 'dryrun@example.invalid' } }
               else { Get-Secrets }

    $accountId = $null
    try {
        $null = Initialize-PoshAcme -Config $Config
        $accountId = Set-AcmeAccount -Config $Config -Email $secrets.Email
    }
    catch {
        if ($DryRun) { Write-Log "[DryRun] Posh-ACME / ACME account setup skipped: $($_.Exception.Message)" -Level WARNING }
        else { throw }
    }

    $issued = @()
    foreach ($dc in $toAdd) {
        $allDomains = @($dc.MainDomain)
        if ($dc.SANs) { $allDomains += @($dc.SANs | Where-Object { $_ }) }
        $sanStr = if (@($dc.SANs | Where-Object { $_ }).Count -gt 0) { " + SANs: $(@($dc.SANs) -join ', ')" } else { '' }
        Write-Log "--- Processing $($dc.MainDomain) [$($dc.Type)]$sanStr ---" -Level INFO

        $verdict = Invoke-DomainValidation -MainDomain $dc.MainDomain -AllDomains $allDomains
        if ($verdict -eq 'Abort') { Write-Log 'Aborting Add flow at the administrator''s request - no changes saved.' -Level WARNING; return }
        if ($verdict -eq 'Skip')  { Write-Log "Skipped $($dc.MainDomain)." -Level WARNING; continue }

        try {
            $cert = New-Certificate -DomainConfig $dc -AllDomains $allDomains -Secrets $secrets
            if ($DryRun) { continue }   # New-Certificate logged WOULD-issue; nothing to persist
            $issued += (ConvertTo-DomainConfigObject -DomainConfig $dc -Cert $cert)
        }
        catch {
            Write-Log "Failed to issue/deploy $($dc.MainDomain): $($_.Exception.Message)" -Level ERROR
        }
    }

    if ($DryRun) {
        Write-Log "[DryRun] WOULD save cert-config.json (PaAccount + $($toAdd.Count) domain(s)) and register the renewal task." -Level INFO
        return
    }
    if ($issued.Count -eq 0) { Write-Log 'No certificates were issued - configuration left unchanged.' -Level WARNING; return }

    # Merge issued domains into the config (existing preserved, same MainDomain replaced), stamp PaAccount.
    $byDomain = [ordered]@{}
    foreach ($d in $existingDomains) { if ($d.MainDomain) { $byDomain[[string]$d.MainDomain] = $d } }
    foreach ($o in $issued) { $byDomain[[string]$o.MainDomain] = $o }
    $merged = @($byDomain.Values | Sort-Object MainDomain)
    $Config | Add-Member -NotePropertyName 'Domains' -NotePropertyValue $merged -Force
    if ($accountId) { $Config | Add-Member -NotePropertyName 'PaAccount' -NotePropertyValue $accountId -Force }
    $null = Set-ConfigVersionStamps -Config $Config
    $null = Save-CertConfig -Config $Config -Reason 'add domains'

    foreach ($o in $issued) {
        Write-EventLogEntry $EID.CertIssued Information "Certificate issued for $($o.MainDomain) [$($o.Type)] (thumbprint $($o.Thumbprint))"
        Send-Telemetry -Config $Config -Outcome ([pscustomobject]@{ Action = 'create'; RunOutcome = 'Issued'; Message = $o.MainDomain })
    }
    if (-not (Register-RenewalTask)) { Write-Log 'Renewal task registration failed - see the error above.' -Level WARNING }
    Write-Log "Add flow complete: $($issued.Count) certificate(s) issued and deployed." -Level SUCCESS
}

function Invoke-DeleteFlow {
    # spec section6 Delete: list managed domains, let the admin select one or more, confirm, and remove
    # them from cert-config.json. When the LAST domain is removed, also unregister the renewal task and
    # offer to remove Renew-Cert.ps1 + cert-config.json. The store certificate itself is left in place
    # (binding cleanup is the admin's call). Emits a delete telemetry event per removed domain.
    param([object] $Config)

    $domains = @(); if ($Config -and $Config.Domains) { $domains = @($Config.Domains) }
    if ($domains.Count -eq 0) { Write-Log 'No managed domains to delete.' -Level INFO; return }

    for ($i = 0; $i -lt $domains.Count; $i++) {
        $d = $domains[$i]
        $sans = if ($d.SANs) { " + SANs: $($d.SANs -join ', ')" } else { '' }
        Write-Log "  [$($i + 1)] $($d.MainDomain) [$($d.Type)]$sans" -Level INFO
    }

    $toDelete = @()
    while ($true) {
        $sel = (Read-Host 'Enter a number to delete (or press Enter to finish)').Trim()
        if ($sel -eq '') { break }
        $idx = 0
        if (-not [int]::TryParse($sel, [ref]$idx)) { Write-Log 'Enter a numeric value.' -Level WARNING; continue }
        $idx--
        if ($idx -lt 0 -or $idx -ge $domains.Count) { Write-Log "Enter a number between 1 and $($domains.Count)." -Level WARNING; continue }
        $name = [string]$domains[$idx].MainDomain
        if ($toDelete -contains $name) { Write-Log "$name already marked for deletion." -Level INFO }
        else { $toDelete += $name; Write-Log "Marked for deletion: $name" -Level WARNING }
    }
    if ($toDelete.Count -eq 0) { Write-Log 'Nothing selected for deletion.' -Level INFO; return }

    Write-Log "Domains to delete: $($toDelete -join ', ')" -Level WARNING
    if ((Read-Host 'Are you sure you want to delete these? (Y/N)').Trim().ToUpper() -ne 'Y') { Write-Log 'Deletion cancelled.' -Level INFO; return }

    $remaining = @($domains | Where-Object { $toDelete -notcontains [string]$_.MainDomain })
    if ($DryRun) {
        Write-Log "[DryRun] WOULD remove $($toDelete.Count) domain(s) from cert-config.json (remaining: $($remaining.Count))." -Level INFO
        if ($remaining.Count -eq 0) { Write-Log '[DryRun] WOULD unregister the renewal task and offer to remove Renew-Cert.ps1 + cert-config.json.' -Level INFO }
        return
    }

    if ($remaining.Count -eq 0) {
        Write-Log 'All domains removed - tearing down the renewal configuration.' -Level WARNING
        $null = Unregister-RenewalTask
        foreach ($name in $toDelete) {
            Write-EventLogEntry $EID.CertDeleted Information "Certificate config removed for $name (last domain)"
            Send-Telemetry -Config $Config -Outcome ([pscustomobject]@{ Action = 'delete'; RunOutcome = 'Removed'; Message = $name })
        }
        if ((Read-Host 'Also remove Renew-Cert.ps1 and cert-config.json? (Y/N)').Trim().ToUpper() -eq 'Y') {
            foreach ($p in $RenewalScript, $ConfigPath) {
                if (Test-Path $p) { Remove-Item -Path $p -Force -ErrorAction SilentlyContinue; Write-Log "Removed $p." -Level SUCCESS }
            }
        }
        else {
            $Config | Add-Member -NotePropertyName 'Domains' -NotePropertyValue @() -Force
            $null = Save-CertConfig -Config $Config -Reason 'delete all domains'
        }
        Write-Log 'Delete flow complete (all domains removed).' -Level SUCCESS
        return
    }

    $Config | Add-Member -NotePropertyName 'Domains' -NotePropertyValue $remaining -Force
    $null = Save-CertConfig -Config $Config -Reason 'delete domains'
    foreach ($name in $toDelete) {
        Write-EventLogEntry $EID.CertDeleted Information "Certificate config removed for $name"
        Send-Telemetry -Config $Config -Outcome ([pscustomobject]@{ Action = 'delete'; RunOutcome = 'Removed'; Message = $name })
    }
    Write-Log "Delete flow complete: removed $($toDelete.Count) domain(s), $($remaining.Count) remaining." -Level SUCCESS
}

function Invoke-CreatorMenu {
    # spec section6 top-level control flow. Returns { SelfReplaced; Failed } so Main can halt for a
    # re-run (SelfReplaced) or exit non-zero on a task-registration failure (Failed).
    param([object] $Config)

    $result = [pscustomobject]@{ SelfReplaced = $false; Failed = $false }
    $domains = @()
    if ($Config -and $Config.Domains) { $domains = @($Config.Domains) }

    if ($domains.Count -eq 0) {
        Write-Log 'No managed domains found - entering Add flow.' -Level INFO
        Invoke-AddFlow -Config $Config
        return $result
    }

    Write-Log "Existing managed domains ($($domains.Count)):" -Level INFO
    foreach ($d in $domains) {
        $sans = if ($d.SANs) { " + SANs: $($d.SANs -join ', ')" } else { '' }
        Write-Log "  $($d.MainDomain) [$($d.Type)]$sans" -Level INFO
    }

    while ($true) {
        $choice = (Read-Host 'Choose an option ([A]dd / [D]elete / [U]pdate-scripts-only / [Q]uit)').Trim().ToUpper()
        switch ($choice) {
            'A' { Invoke-AddFlow -Config $Config; return $result }
            'D' { Invoke-DeleteFlow -Config $Config; return $result }
            'U' {
                Write-Log 'Update-scripts-only: re-running self-update and re-registering the scheduled task.' -Level INFO
                if (Invoke-CreatorSelfUpdate -Config $Config) { $result.SelfReplaced = $true; return $result }
                if (-not (Register-RenewalTask)) { $result.Failed = $true }
                return $result
            }
            'Q' { Write-Log 'Quit.' -Level INFO; return $result }
            default { Write-Log 'Invalid choice. Enter A, D, U, or Q.' -Level WARNING }
        }
    }
}

#endregion Interactive menu ---------------------------------------------------

#region Main ------------------------------------------------------------------

# Log dir + transcript rotation (keep 90 days), mirror renewal.
try {
    if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
    Get-ChildItem $LogDir -Filter 'cert-create-*.log' -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-90) } | Remove-Item -Force -ErrorAction SilentlyContinue
}
catch { }

$transcriptPath = Join-Path $LogDir ("cert-create-{0}.log" -f (Get-Date -Format 'yyyy-MM-dd-HH_mm_ss'))
try { Start-Transcript -Path $transcriptPath -Append | Out-Null } catch { }

$exitCode = 0
try {
    Write-Log "=== Create-New-Cert v$ScriptVersion starting (DryRun=$DryRun, CheckOnly=$CheckOnly, SkipSelfUpdate=$SkipSelfUpdate) ===" -Level INFO
    Write-EventLogEntry $EID.Start Information "Create-New-Cert v$ScriptVersion starting"

    # Config directory must exist / be writable (fatal otherwise, spec section10).
    if (-not (Test-Path $CertRenewalPath)) {
        if ($DryRun) { Write-Log "[DryRun] WOULD create config directory $CertRenewalPath." -Level INFO }
        else { New-Item -ItemType Directory -Path $CertRenewalPath -Force | Out-Null }
    }

    $config = if (Test-Path $ConfigPath) { Get-CertConfig } else { $null }

    if ($CheckOnly) {
        $renewalVer = Get-OnDiskScriptVersion -Path $RenewalScript
        $domains    = if ($config -and $config.Domains) { @($config.Domains) } else { @() }
        $renewalStr = if ($renewalVer) { $renewalVer } else { '(absent)' }
        $configStr  = if ($config) { 'present' } else { 'absent' }
        $secretsStr = if (Test-Path $SecretsPath) { 'present' } else { 'absent' }
        Write-Log "CheckOnly: creator=$ScriptVersion renewal-on-disk=$renewalStr config=$configStr secrets=$secretsStr certs=$($domains.Count)" -Level INFO
        foreach ($d in $domains) {
            $sans = if ($d.SANs) { " + SANs: $($d.SANs -join ', ')" } else { '' }
            Write-Log "  $($d.MainDomain) [$($d.Type)]$sans" -Level INFO
        }
        Write-Log 'CheckOnly complete.' -Level SUCCESS
    }
    else {
        # (section3) Two-script self-update + its telemetry event (Decision C).
        $selfReplaced = $false
        if (-not $SkipSelfUpdate) {
            $selfReplaced = Invoke-CreatorSelfUpdate -Config $config
            Send-Telemetry -Config $config -Outcome ([pscustomobject]@{ Action = 'self-update'; RunOutcome = $(if ($selfReplaced) { 'CreatorReplaced' } else { 'Checked' }) })
        }
        else { Write-Log 'Self-update skipped (-SkipSelfUpdate).' -Level INFO }

        if (-not $selfReplaced) {
            # The renewal script must be present before we can register the task or issue (fatal, spec
            # section10). Tolerated under -SkipSelfUpdate / -DryRun (test isolation; nothing was downloaded).
            if (-not $SkipSelfUpdate -and -not $DryRun -and -not (Test-Path $RenewalScript)) {
                throw "Renew-Cert.ps1 is missing at $RenewalScript and could not be downloaded from the manifest."
            }

            # (section5) Billing block (the only interactive credential-ish input).
            $config = Read-BillingPrompts -Config $config

            # (section6) Interactive Add/Delete/Update menu. The vault secrets sync runs lazily inside the
            # issuance path (Initialize-VaultSecrets), so non-issuing choices ([U]/[D]/[Q]) skip the Azure
            # round-trip (spec section4: before issuance).
            $menu = Invoke-CreatorMenu -Config $config
            if ($menu.SelfReplaced) { $selfReplaced = $true }
            elseif ($menu.Failed) { $exitCode = 1; Write-Log 'Scheduled-task registration failed - see the error above.' -Level ERROR }
        }

        # Single halt point (Decision A): after replacing its own file the creator stops and asks for a re-run.
        if ($selfReplaced) {
            Write-Log 'Creator updated itself. Please re-run Create-New-Cert.ps1 to continue.' -Level WARNING
        }
        elseif ($exitCode -eq 0) {
            Write-Log '=== Create-New-Cert finished ===' -Level SUCCESS
        }
    }
}
catch {
    # Fatal startup failure (config dir, vault sync, missing renewal download) reaches here (spec section10).
    Write-Log "FATAL: $($_.Exception.Message)" -Level ERROR
    Write-EventLogEntry $EID.Start Error "Fatal startup failure: $($_.Exception.Message)"
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
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAve/sax59j03c7
# pbN+KSA3Sb0RN5Tty28PuVgvpjl1NqCCF6gwggRqMIIC0qADAgECAhA9a+7a4tnR
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
# gjcCARUwLwYJKoZIhvcNAQkEMSIEIFnJ9i7tQJCXBlpE6eEIVvz4pzYikFMI/2xH
# UE31q8WAMA0GCSqGSIb3DQEBAQUABIIBgBlAm/VyOMQk8uyX+VLXE+8qT9Dwi0Fk
# N6tTx76v5CBppRsmSUEfFpK88VjakbRs1uUHLUvIWLDw3iHkc6EXC4ZW6mTzNOy+
# MgV1sFYfenpEoIK9t+MFq8ShRRNmdyr9BdIXtxypxouSlsu8IEr4eHqf6+io5OTU
# j5MtYk1Z0cTE722GKucwX98Cu/CEAbxQBrecc2e46R+QGykSlhct99CMouwmvnfA
# KOgxfSWRveOpFndn063n0+Yi1oKX9crHf4gXYoiosWD4sWaoI+TSTdmuWWpccy4Q
# MPuvLcEUy24jNFM57EtxEDqLxGABEnzUw76rSRefoD3dBCym7p1pz4tyKcf7y5/3
# KbdF8JmkHwjkgf7ENOV+pOs7E/SePK913gUtDN2EmeJJrP9IDLj7Y2+2MIF8yY6p
# Zx3y7yjMBSS4j7VNcDuf1G/iINKrbkE8FsKKFjK1cseqDmOFgC9kCp9/UU3dyhkb
# ZrujKbb6JeJ/fAygHCsug7mgg0clDarq/KGCAyYwggMiBgkqhkiG9w0BCQYxggMT
# MIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5j
# LjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNB
# NDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZIAWUD
# BAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEP
# Fw0yNjA2MTcxMzI2MTRaMC8GCSqGSIb3DQEJBDEiBCDU42xbDcS9G9m4yWP9p3Rt
# OTF5vChj3nUiaREvAczXPjANBgkqhkiG9w0BAQEFAASCAgCZHt2D+JhQEkYW/ATj
# zDnbkBTXzcD3WVOqUIDZVXpARKz/6cUS6JtdndSkQMCnLsHHB02aQe1spaMr5kzW
# CP/W5C4Gfp/AOGzy9W05tQ6VxFk/A8yjMFT4GBmogjzxpxKcIuqibP7gi1SHdUKB
# uILP6p+n4VyHcpX/KGjDqV9+W5Edvx9dQ413CfPzKI9erI6rTft06HmIwwnawLHM
# RQrwhDrPDfVcIVVEbGTiTvPoiXNqOOLENJ4h7oDD5eew9Mk15F3ekPAKLTZgiZb4
# EupKEcMfiqSOhATdHSSlBAzI0g+vET8JVo6Pxsv91/2hMQr3lOUFcHCg+g8Mb4ER
# GPj0EdKznB48ixm46dX5bLA2IC7Am4YaRHkvj0ysqEe7ZOLe4xWmlqj08FL/fA7f
# JoowQfhq/iTRn/Qcvy3wUY/hnSKqQlLCoG5E42WLCBWk21Mp/wt/VjMAGto7c9xG
# vwZR+1jSLjD1wcPXQQSlKmGsmpQ+AU3ypFgTeX202j0KGMjbdVjHNmHAvua1ILc4
# ZizgUGfgqZZIEcXohHnSAaUmNdqP5aUjTK1E4C60Sh+gM3bNhmlEWzJScRNJiRWG
# cLBsT++TgOXH1emTCAdNpGmPf9X1VlqG7gmm/tYBEhRXO9+ei0XUlXhorNrHrmmI
# ERNn5HiwiKzDWvIy6MsS2aO5DA==
# SIG # End signature block
