#Requires -Version 5.1
<#
.SYNOPSIS
  Renewal script for cert-renewal v2. Runs daily as NT AUTHORITY\SYSTEM via Scheduled Task.
.DESCRIPTION
  v2 plumbing (PR A): load cert-config.json, load + DPAPI-LM decrypt cert-secrets.json,
  self-update from the manifest (sha256 + Authenticode thumbprint gate + circuit-breaker +
  PinVersion), local logging (transcript + Windows Event Log), a Teams failure card, and a
  best-effort Send-Telemetry event (Azure Monitor Logs Ingestion -> CertRenewal_CL, the fleet
  liveness/inventory/billing signal; never blocks renewal). Renewal core (PR B, ported from v1): per-domain binding detection
  (netsh / IIS Web / IIS FTP) + config validation incl. the automatic CertStore->Netsh upgrade,
  Submit-Renewal with stale-authorization (-Force) recovery, self-heal via New-PACertificate
  when Posh-ACME has lost track of an order, per-Type deploy, old-cert cleanup, optional
  service restart (see docs/phase1-renew-cert-spec.md section9). Domeneshop creds (self-heal only) and
  the Teams webhook come from cert-secrets.json, which the daily run best-effort refreshes from Azure
  Key Vault (Decision D2, SP-cert auth via cert-config.Telemetry) so a rotated token/webhook reaches a
  box that never re-runs the creator. No periodic Teams heartbeat - the per-run
  telemetry event to Log Analytics is the liveness signal (docs/telemetry-log-analytics-setup.md).
.PARAMETER DryRun
  Read-only: log what WOULD happen; no self-update replace, no renew/deploy, no Teams/telemetry POST.
.PARAMETER ManifestUrl
  Override the manifest URL (test channel). Else cert-config.ManifestUrl, else the built-in prod URL.
.PARAMETER SkipSelfUpdate
  Skip the self-update check (isolate renewal logic in tests).
.PARAMETER CheckOnly
  Print version + certificate inventory and exit (ad-hoc audit). Skips secrets, self-update, renewal.
.PARAMETER Force
  Renew every managed certificate now, ignoring the expiry threshold (forced rotation, or to exercise
  the pre/post-renewal hooks on demand). Honors -DryRun. Old-cert cleanup is unchanged.
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
    [switch] $Force      # renew every managed cert now, ignoring the expiry threshold (forced rotation / hook testing)
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue   # for DPAPI ProtectedData

# CI replaces 'DEV' with the release tag (e.g. 2.0.0) at publish time.
$ScriptVersion = '2.4.0'

# Self-signed code-signing thumbprints trusted for self-updates (array = rotation overlap).
# Enforced by THIS running script before any atomic replace; never relax via config/manifest.
# See docs/code-signing.md.
$AllowedSignerThumbprints = @(
    '96705BBE468876FC2E48D27F3E7827500CF636E5'   # Iteam AS Cert-Renewal Code Signing (2026-06-04 .. 2036)
)

# Built-in production manifest URL (overridable via -ManifestUrl or cert-config.ManifestUrl test channel).
$DefaultManifestUrl = 'https://raw.githubusercontent.com/iteam-as/public-certrenewal/main/manifest.json'

# Renew (and prune the superseded cert) once a certificate has this many days or fewer remaining.
$RenewalThresholdDays = 30

# Shared-secrets Key Vault (Decision D2/D3). The daily SYSTEM renewal best-effort refreshes
# cert-secrets.json from here so a rotated Domeneshop token / Teams webhook reaches a box that never
# re-runs the creator. Vault name overridable via cert-config.SecretsVault. Field -> vault secret name.
$DefaultSecretsVaultName = 'kv-online-nwe-prod-1'
$SecretNameMap = [ordered]@{
    DomeneshopToken  = 'DomeneshopToken'
    DomeneshopSecret = 'DomeneshopSecret'
    TeamsWebhookUrl  = 'TeamsWebhookUrl'
    Email            = 'Email'
}

# Paths
$CertRenewalPath = 'C:\Cert\Renewal'
$ConfigPath      = Join-Path $CertRenewalPath 'cert-config.json'
$SecretsPath     = Join-Path $CertRenewalPath 'cert-secrets.json'
$SelfUpdateState = Join-Path $CertRenewalPath 'selfupdate-state.json'
$LogDir          = Join-Path $CertRenewalPath 'log'
$SelfPath        = $PSCommandPath        # this script's own path, for the atomic self-replace

# Windows Event Log
$EventLogName   = 'Application'
$EventLogSource = 'CertRenewal'
$EID = @{ Start = 1000; UpToDate = 1001; Upgraded = 1010; RenewSuccess = 1020; RenewFailure = 1030; HookFailed = 1031; SigRefused = 1040; SecretsRefreshed = 1045; Breaker = 1050 }

# Self-update outcome stamped onto the telemetry event (UpToDate | Upgraded | Refused | Skipped).
# Set by Invoke-SelfUpdate / main; defaults to Skipped so it is always defined for Send-Telemetry.
$SelfUpdateStatus = 'Skipped'

#region Helpers ---------------------------------------------------------------

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

function Send-TeamsNotification {
    # Failure-only Adaptive Card (ported from v1). Best-effort; never throws.
    param(
        [string] $WebhookUrl,
        [string] $Title,
        [string] $Message,
        [ValidateSet('good', 'warning', 'attention')][string] $Severity = 'attention',
        [hashtable] $Facts = @{}
    )
    if ([string]::IsNullOrWhiteSpace($WebhookUrl)) { Write-Log 'Teams webhook not configured; skipping notification.' -Level WARNING; return }
    if ($DryRun) { Write-Log "[DryRun] WOULD send Teams card: $Title" -Level INFO; return }
    try {
        $factsList = foreach ($k in $Facts.Keys) { @{ title = $k; value = [string]$Facts[$k] } }
        $payload = @{
            type        = 'message'
            attachments = @(@{
                contentType = 'application/vnd.microsoft.card.adaptive'
                content     = @{
                    type     = 'AdaptiveCard'
                    version  = '1.4'
                    '$schema' = 'http://adaptivecards.io/schemas/adaptive-card.json'
                    body     = @(
                        @{ type = 'TextBlock'; size = 'Large'; weight = 'Bolder'; text = $Title; wrap = $true; color = $Severity }
                        @{ type = 'TextBlock'; text = $Message; wrap = $true }
                        @{ type = 'FactSet'; facts = @($factsList) }
                    )
                }
            })
        } | ConvertTo-Json -Depth 12
        Invoke-RestMethod -Uri $WebhookUrl -Method Post -Body $payload -ContentType 'application/json' -TimeoutSec 20 | Out-Null
        Write-Log 'Teams notification sent.' -Level SUCCESS
    }
    catch { Write-Log "Failed to send Teams notification: $($_.Exception.Message)" -Level WARNING }
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

function New-TelemetryEvent {
    # RENEWAL-ONLY helper (NOT part of the shared/diff-able set - the creator/bootstrap emit single events
    # directly). Builds one pre-stamped work-event consumed by Send-Telemetry's per-event loop so the LA
    # timeline reflects when the work actually happened (TimeGenerated stamped here, at the event).
    param(
        [Parameter(Mandatory)][string] $Action,
        [string] $Domain,
        [string] $RunOutcome,
        [string] $Message
    )
    [pscustomobject]@{
        Action        = $Action
        Domain        = $Domain
        RunOutcome    = $RunOutcome
        Message       = $Message
        TimeGenerated = (Get-Date).ToUniversalTime().ToString('o')
    }
}

function Invoke-SelfUpdate {
    # Returns $true if the script replaced itself (caller should exit 0 so next run uses the new version).
    param([Parameter(Mandatory)][object] $Config)

    if (-not $SelfPath) { Write-Log 'Cannot resolve own path ($PSCommandPath empty); skipping self-update.' -Level WARNING; return $false }

    $url = if ($ManifestUrl) { $ManifestUrl } elseif ($Config.ManifestUrl) { $Config.ManifestUrl } else { $DefaultManifestUrl }

    if ($Config.PinVersion) {
        Write-Log "PinVersion=$($Config.PinVersion) set in cert-config - skipping self-update." -Level INFO
        $script:SelfUpdateStatus = 'Skipped'
        return $false
    }

    $state = Get-SelfUpdateState
    if ([int]$state.consecutiveFailures -ge 2 -and $state.lastAttemptUtc) {
        # lastAttemptUtc is stored as a UTC ISO string; on PS 5.1 the [datetime] cast yields a
        # LOCAL-kind value, so normalize back to UTC or the window is skewed by the UTC offset
        # (observed live as "last -2,0h ago" on a UTC+2 box = 26h backoff instead of 24h).
        $sinceH = ((Get-Date).ToUniversalTime() - ([datetime]$state.lastAttemptUtc).ToUniversalTime()).TotalHours
        if ($sinceH -lt 24) {
            Write-Log ("Self-update circuit-breaker open ({0} consecutive fails, last {1:N1}h ago) - backing off 24h." -f $state.consecutiveFailures, $sinceH) -Level WARNING
            Write-EventLogEntry $EID.Breaker Warning "Self-update circuit-breaker open ($($state.consecutiveFailures) fails)"
            $script:SelfUpdateStatus = 'Refused'
            return $false
        }
    }

    try {
        Write-Log "Self-update: fetching manifest $url" -Level INFO
        $manifest = Invoke-WithRetry -OperationName 'manifest fetch' -ScriptBlock { Invoke-RestMethod -Uri $url -TimeoutSec 15 -UseBasicParsing }
        $latest = [string]$manifest.renewal.version
        if (-not $latest) { throw 'manifest has no renewal.version' }

        if ((Compare-SemVer $ScriptVersion $latest) -ge 0) {
            Write-Log "Renewal script up to date (current $ScriptVersion, manifest $latest)." -Level SUCCESS
            Write-EventLogEntry $EID.UpToDate Information "Up to date at $ScriptVersion"
            $state.consecutiveFailures = 0; Save-SelfUpdateState $state
            $script:SelfUpdateStatus = 'UpToDate'
            return $false
        }

        if ($DryRun) { Write-Log "[DryRun] WOULD upgrade $ScriptVersion -> $latest from $($manifest.renewal.url)" -Level INFO; $script:SelfUpdateStatus = 'Skipped'; return $false }

        # The download target MUST keep a .ps1 extension: Get-AuthenticodeSignature resolves
        # its signature parser (SIP) from the extension, so a '.new' file always reads as
        # "not signed" and the gate would refuse every update (caught by the section-12 lab).
        $newPath = Join-Path (Split-Path $SelfPath -Parent) ([IO.Path]::GetFileNameWithoutExtension($SelfPath) + '.new.ps1')
        Write-Log "Downloading renewal $latest from $($manifest.renewal.url)" -Level INFO
        Invoke-WithRetry -OperationName 'script download' -ScriptBlock { Invoke-WebRequest -Uri $manifest.renewal.url -OutFile $newPath -TimeoutSec 30 -UseBasicParsing } | Out-Null

        $hash = (Get-FileHash $newPath -Algorithm SHA256).Hash.ToLower()
        if ($hash -ne ([string]$manifest.renewal.sha256).ToLower()) {
            Remove-Item $newPath -Force -ErrorAction SilentlyContinue
            $script:SelfUpdateStatus = 'Refused'
            throw "sha256 mismatch (downloaded $hash, manifest $($manifest.renewal.sha256))"
        }

        $auth = Test-AuthenticodeAllowed -FilePath $newPath
        if (-not $auth.Allowed) {
            Remove-Item $newPath -Force -ErrorAction SilentlyContinue
            Write-EventLogEntry $EID.SigRefused Error "Self-update signature refused: $($auth.Reason)"
            $script:SelfUpdateStatus = 'Refused'
            throw "signature refused ($($auth.Reason))"
        }

        Move-Item -Path $newPath -Destination $SelfPath -Force   # atomic on NTFS
        Write-Log "Upgraded renewal script $ScriptVersion -> $latest (signer $($auth.Thumbprint)). Next run executes the new version." -Level SUCCESS
        Write-EventLogEntry $EID.Upgraded Information "Upgraded $ScriptVersion -> $latest"
        $state.consecutiveFailures = 0; Save-SelfUpdateState $state
        $script:SelfUpdateStatus = 'Upgraded'
        return $true
    }
    catch {
        $state.consecutiveFailures = [int]$state.consecutiveFailures + 1
        $state.lastAttemptUtc = (Get-Date).ToUniversalTime().ToString('o')
        Save-SelfUpdateState $state
        Write-Log "Self-update failed (attempt $($state.consecutiveFailures)): $($_.Exception.Message). Continuing on current version $ScriptVersion." -Level ERROR
        return $false
    }
}

#endregion Helpers ------------------------------------------------------------

#region Key Vault secret refresh (Decision D2) --------------------------------
# Daily SYSTEM rotation handling: a box can run for years on the renewal task without the creator ever
# being re-run, so renewal is the only place a rotated Domeneshop token / Teams webhook reliably reaches
# the fleet. Pure helpers below are COPIED VERBATIM from Create-New-Cert.ps1 (keep them byte-identical so
# the two files stay diff-able). Connect-SecretsVault / Sync-SecretsFromVault DELIBERATELY differ from the
# creator: identity comes from cert-config.Telemetry (renewal as SYSTEM has no built-in constants), and the
# whole thing is BEST-EFFORT (Update-SecretsFromVault swallows every failure) where the creator hard-aborts.

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

function Get-ResolvedVaultName {
    # cert-config.SecretsVault override, else the built-in default. (Renewal has no -VaultName parameter;
    # the creator's copy also accepts a -VaultName switch.)
    param([object] $Config)
    if ($Config -and $Config.SecretsVault) { return $Config.SecretsVault }
    return $DefaultSecretsVaultName
}

function Connect-SecretsVault {
    # App-only sign-in to Azure with the shared telemetry SP cert (Decision D2/D3). Identity is passed in
    # from cert-config.Telemetry (renewal as SYSTEM has no built-in constants - that's the creator's path).
    # Throws if a module / the cert / the connection is missing; the best-effort caller swallows it.
    param(
        [Parameter(Mandatory)][string] $TenantId,
        [Parameter(Mandatory)][string] $AppClientId,
        [Parameter(Mandatory)][string] $CertThumbprint
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
        Connect-AzAccount -ServicePrincipal -ApplicationId $AppClientId -CertificateThumbprint $CertThumbprint `
            -Tenant $TenantId -ErrorAction Stop | Out-Null
    }
    Write-Log "Connected to Azure as SP $AppClientId (tenant $TenantId)." -Level SUCCESS
}

function Sync-SecretsFromVault {
    # Decision D2. Connect to the vault (SP cert), fetch the 4 current values, and rewrite cert-secrets.json
    # IFF the file is absent or a value rotated. Idempotent (no change -> no rewrite). Logs changed FIELD
    # NAMES only, never values. Returns $true if it rewrote the file. Throws on vault failure; the
    # best-effort caller (Update-SecretsFromVault) swallows it so renewal never blocks on the vault.
    # (Mirrors the creator's Sync-SecretsFromVault; differs only in config-driven auth + EID 1045.)
    param(
        [Parameter(Mandatory)][string] $VaultName,
        [Parameter(Mandatory)][object] $Telemetry
    )

    Write-Log "Syncing shared secrets from Key Vault '$VaultName'..." -Level INFO
    Connect-SecretsVault -TenantId $Telemetry.TenantId -AppClientId $Telemetry.AppClientId -CertThumbprint $Telemetry.CertThumbprint

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
    Write-EventLogEntry $EID.SecretsRefreshed Information ("cert-secrets.json refreshed (fields: {0})" -f ($changed -join ', '))
    return $true
}

function Update-SecretsFromVault {
    # Decision D2 best-effort entry point for the daily SYSTEM renewal: refresh cert-secrets.json from the
    # vault, but NEVER block renewal. Skips silently when there is no cert-config.Telemetry SP identity
    # (nothing to auth with), and swallows every failure (missing module / cert / vault unreachable) so
    # renewal continues on the last-known-good local secrets. (The creator aborts in the same spot because
    # it must not issue with a stale token; the daily renewal must run regardless.)
    param([Parameter(Mandatory)][object] $Config)

    $t = $Config.Telemetry
    if (-not $t -or [string]::IsNullOrWhiteSpace([string]$t.TenantId) -or
        [string]::IsNullOrWhiteSpace([string]$t.AppClientId) -or
        [string]::IsNullOrWhiteSpace([string]$t.CertThumbprint)) {
        Write-Log 'No cert-config.Telemetry SP identity; skipping vault secret refresh (using local cert-secrets.json).' -Level DEBUG
        return
    }
    $vaultName = Get-ResolvedVaultName -Config $Config
    try { $null = Sync-SecretsFromVault -VaultName $vaultName -Telemetry $t }
    catch { Write-Log "Vault secret refresh skipped (non-fatal): $($_.Exception.Message)" -Level WARNING }
}

#endregion Key Vault secret refresh -------------------------------------------

#region Renewal core (ported from v1) ------------------------------------------
# Faithful port of the proven v1 renewal logic (BHP-Leveranse/Cert/Create-New-Cert-SharedConfig.ps1,
# generated here-string ~1766-3330), de-escaped, converted to Write-Log, with the hardcoded
# Domeneshop creds / Teams webhook swapped for cert-secrets.json (spec section4). Every mutating action
# (renew / deploy / rebind / cert cleanup / service restart / config save) is DryRun-gated.

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

function Test-IsIISWebAppId {
    # True when a netsh sslcert appid is IIS's well-known http.sys appid. A no-SNI IIS Web binding
    # (sslFlags=0) is stored by http.sys IP-based at 0.0.0.0:443 under THIS appid, so the same physical
    # binding surfaces as BOTH Netsh and IIS Web; the appid is the discriminator that it is really
    # IIS-owned (issue #49). Compared brace-, whitespace- and case-insensitively.
    param([string] $AppId)
    if ([string]::IsNullOrWhiteSpace($AppId)) { return $false }
    return ((($AppId -replace '[{}\s]', '').ToLower()) -eq '4dc3e181-e14b-4a21-b022-59fc669b0914')
}

function Get-IISWebBindingsForThumbprint {
    # All IIS https site bindings using cert $Thumbprint -> @( @{ SiteName; BindingInformation } ).
    param([string] $Thumbprint)
    $found = @()
    if (-not (Get-Module -ListAvailable -Name WebAdministration)) { return $found }
    Import-Module WebAdministration -ErrorAction SilentlyContinue
    $normalized = ($Thumbprint -replace '[\s:]', '').ToUpper()
    $sites = Get-ChildItem -Path IIS:\Sites -ErrorAction SilentlyContinue
    foreach ($site in $sites) {
        $httpsBindings = $site.bindings.collection | Where-Object { $_.protocol -eq 'https' }
        foreach ($b in $httpsBindings) {
            try {
                if ($b.certificateHash -and ((($b.certificateHash -replace '[\s:]', '').ToUpper()) -eq $normalized)) {
                    $found += [pscustomobject]@{ SiteName = $site.Name; BindingInformation = $b.bindingInformation }
                }
            }
            catch { }   # skip bindings without a certificate
        }
    }
    return @($found)
}

function Get-IISFTPBindingsForThumbprint {
    # All IIS FTP sites using cert $Thumbprint -> @( @{ SiteName } ).
    param([string] $Thumbprint)
    $found = @()
    if (-not (Get-Module -ListAvailable -Name WebAdministration)) { return $found }
    Import-Module WebAdministration -ErrorAction SilentlyContinue
    $normalized = ($Thumbprint -replace '[\s:]', '').ToUpper()
    $ftpSites = Get-ChildItem -Path IIS:\Sites -ErrorAction SilentlyContinue | Where-Object {
        $_.bindings.collection.protocol -contains 'ftp'
    }
    foreach ($site in $ftpSites) {
        try {
            $ftpProp = Get-ItemProperty -Path "IIS:\Sites\$($site.Name)" -Name ftpServer.security.ssl.serverCertHash -ErrorAction SilentlyContinue
            $ftpHash = if ($ftpProp.ftpServer.security.ssl.serverCertHash) { $ftpProp.ftpServer.security.ssl.serverCertHash } else { $ftpProp }
            if ($ftpHash -and ((([string]$ftpHash -replace '[\s:]', '').ToUpper()) -eq $normalized)) {
                $found += [pscustomobject]@{ SiteName = $site.Name }
            }
        }
        catch { }   # skip sites without SSL
    }
    return @($found)
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

function Get-ExistingIISWebBindingsForDomain {
    param([string] $Domain)
    try {
        $cert = Get-StoreCertificateForDomain -Domain $Domain
        if (-not $cert) { return $null }
        # @(...) so a single match doesn't unwrap to a bare PSCustomObject (whose .Count is $null).
        $bindings = @(Get-IISWebBindingsForThumbprint -Thumbprint $cert.Thumbprint)
        if ($bindings.Count -gt 0) {
            Write-Log "  Found $($bindings.Count) existing IIS Web binding(s): $(($bindings | ForEach-Object { "$($_.SiteName) [$($_.BindingInformation)]" }) -join ', ')" -Level INFO
            return @{ Bindings = $bindings; Certificate = $cert }
        }
        return $null
    }
    catch {
        Write-Log "Error scanning for existing IIS Web bindings: $($_.Exception.Message)" -Level WARNING
        return $null
    }
}

function Get-ExistingIISFTPBindingsForDomain {
    param([string] $Domain)
    try {
        $cert = Get-StoreCertificateForDomain -Domain $Domain
        if (-not $cert) { return $null }
        # @(...) so a single match doesn't unwrap to a bare PSCustomObject (whose .Count is $null).
        $bindings = @(Get-IISFTPBindingsForThumbprint -Thumbprint $cert.Thumbprint)
        if ($bindings.Count -gt 0) {
            Write-Log "  Found $($bindings.Count) existing IIS FTP binding(s): $(($bindings | ForEach-Object { $_.SiteName }) -join ', ')" -Level INFO
            return @{ Bindings = $bindings; Certificate = $cert }
        }
        return $null
    }
    catch {
        Write-Log "Error scanning for existing IIS FTP bindings: $($_.Exception.Message)" -Level WARNING
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

function Invoke-SelfHealCertificate {
    # Posh-ACME has lost track of a cert (e.g. order stuck in 'pending' after a failed
    # Submit-Renewal -Force): rebuild the order from scratch with New-PACertificate -Force.
    # Captures bindings against the OLD thumbprint (from cert-config) BEFORE issuing - after the
    # new cert is installed, domain-based lookups would resolve to the new cert instead.
    # Returns the new PACertificate object on success; throws on failure.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '',
        Justification = 'Domeneshop secret is DPAPI-LM encrypted at rest (cert-secrets.json); the Posh-ACME plugin requires a SecureString at runtime.')]
    param(
        [Parameter(Mandatory)][string] $Domain,
        [string[]] $SANs,
        [string] $OldThumbprint,
        [Parameter(Mandatory)][object] $Secrets
    )

    Write-Log "=== Self-heal: reissuing certificate for $Domain (old thumbprint: $OldThumbprint) ===" -Level WARNING

    $allDomains = @($Domain)
    if ($SANs) { $allDomains += @($SANs | Where-Object { $_ }) }

    # One DnsAlias per domain, using the certval.no CNAME pattern
    $dnsAliasArray = @()
    foreach ($d in $allDomains) {
        $suffix = Get-DomainSuffix -FQDN $d
        $dnsAliasArray += Get-AcmeChallengeDomain -Domain "$suffix.certval.no"
    }
    Write-Log "  Domains: $($allDomains -join ', ')" -Level INFO
    Write-Log "  DnsAlias: $($dnsAliasArray -join ', ')" -Level INFO

    $oldNetshBindings  = $null
    $oldIISWebBindings = @()
    $oldIISFTPBindings = @()
    if ($OldThumbprint) {
        $oldNetshBindings = Get-NetshBindingForCertificate -Thumbprint $OldThumbprint
        if ($oldNetshBindings) { Write-Log "  Captured $($oldNetshBindings.Bindings.Count) netsh binding(s) against old thumbprint" -Level INFO }
        try {
            $oldIISWebBindings = @(Get-IISWebBindingsForThumbprint -Thumbprint $OldThumbprint)
            if ($oldIISWebBindings.Count -gt 0) { Write-Log "  Captured $($oldIISWebBindings.Count) IIS Web binding(s) against old thumbprint" -Level INFO }
            $oldIISFTPBindings = @(Get-IISFTPBindingsForThumbprint -Thumbprint $OldThumbprint)
            if ($oldIISFTPBindings.Count -gt 0) { Write-Log "  Captured $($oldIISFTPBindings.Count) IIS FTP binding(s) against old thumbprint" -Level INFO }
        }
        catch { Write-Log "  Error capturing IIS bindings: $($_.Exception.Message)" -Level WARNING }
    }

    # Issue fresh certificate. New-PACertificate -Force creates a brand-new order with fresh
    # authorizations and stores the plugin config on the order for future Submit-Renewal calls.
    # Domeneshop creds come from cert-secrets.json - the self-heal path is their only consumer
    # (normal renewals use Posh-ACME's per-order encrypted plugin args, spec section4).
    Write-Log '  Requesting fresh certificate from the ACME server...' -Level INFO
    $pluginArgs = @{
        DomeneshopToken  = $Secrets.DomeneshopToken
        DomeneshopSecret = (ConvertTo-SecureString -String $Secrets.DomeneshopSecret -AsPlainText -Force)
    }
    $poshParams = @{
        Domain     = $allDomains
        Plugin     = 'Domeneshop'
        PluginArgs = $pluginArgs
        DnsAlias   = $dnsAliasArray
        AcceptTOS  = $true
        Force      = $true
    }
    if ($Secrets.Email) { $poshParams.Contact = $Secrets.Email }
    $newCert = Invoke-WithRetry -OperationName "Self-heal issuance for $Domain" -MaxRetries 3 -InitialDelaySeconds 10 -ScriptBlock {
        New-PACertificate @poshParams
    }
    Write-Log "  New certificate issued: thumbprint=$($newCert.Thumbprint), expires=$($newCert.NotAfter)" -Level SUCCESS

    Install-PACertificate -PACertificate $newCert -StoreLocation LocalMachine -StoreName My
    Write-Log '  Installed to LocalMachine\My' -Level SUCCESS

    # Rebind everything captured against the old thumbprint
    if ($oldNetshBindings) {
        foreach ($b in $oldNetshBindings.Bindings) {
            $null = Update-NetshBinding -IpPort $b.IpPort -BindingKey $b.BindingKey -AppId $b.AppId -Thumbprint $newCert.Thumbprint
        }
    }
    foreach ($b in $oldIISWebBindings) {
        $null = Update-IISWebBinding -SiteName $b.SiteName -BindingInformation $b.BindingInformation -Thumbprint $newCert.Thumbprint
    }
    foreach ($b in $oldIISFTPBindings) {
        $null = Update-IISFTPBinding -SiteName $b.SiteName -Thumbprint $newCert.Thumbprint
    }

    # Remove the old cert from the store now that nothing points at it
    if ($OldThumbprint) {
        try {
            if (Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Thumbprint -eq $OldThumbprint }) {
                Remove-Item -Path "Cert:\LocalMachine\My\$OldThumbprint" -Force -ErrorAction Stop
                Write-Log "  Removed old certificate $OldThumbprint from store" -Level SUCCESS
            }
        }
        catch { Write-Log "  Could not remove old cert ${OldThumbprint}: $($_.Exception.Message)" -Level WARNING }
    }

    Write-Log "Self-heal completed for $Domain (new thumbprint: $($newCert.Thumbprint))" -Level SUCCESS
    return $newCert
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

function Get-TeamsFacts {
    # Standard fact set for Teams cards, incl. Billing identifiers (spec section9).
    param([object] $Config)
    $facts = @{
        'Server'    = $env:COMPUTERNAME
        'Version'   = $ScriptVersion
        'Timestamp' = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    }
    if ($Config.Billing) {
        if ($Config.Billing.CustomerName) {
            $facts['Customer'] = if ($Config.Billing.Abr) { '{0} ({1})' -f $Config.Billing.CustomerName, $Config.Billing.Abr } else { [string]$Config.Billing.CustomerName }
        }
        if ($Config.Billing.CustomerNr)  { $facts['Customer Nr'] = [string]$Config.Billing.CustomerNr }
        if ($Config.Billing.InvoiceCode) { $facts['Invoice Code'] = [string]$Config.Billing.InvoiceCode }
    }
    return $facts
}

function Invoke-RenewalHook {
    # Issue #13 - best-effort SYSTEM execution of an admin-supplied .ps1 around a renewal
    # (PreRenewalScript / PostRenewalScript on a domain). Renewal context is exposed via
    # $env:CERTRENEWAL_HOOK_* (NOT script parameters) so any existing script runs unmodified - no
    # required param() block, no parameter-binding errors. Best-effort: a missing/failing/non-zero hook
    # logs WARNING + the HookFailed event and NEVER throws (a failed Pre hook must not block the renewal;
    # a failed Post hook rolls nothing back). -DryRun => log WOULD + no-op. Only non-secret cert metadata
    # is exported/logged. The hook runs as SYSTEM (the renewal task identity) - operations-guide documents
    # that the .ps1 must therefore live somewhere only admins can write.
    # RETURNS a status string ('Ran' | 'Failed' | 'Skipped' | 'DryRun') so the caller can emit a telemetry
    # event - callers MUST capture it. Hook stdout/stderr is routed to the DEBUG log so it can never leak
    # into the renewal output stream (PS implicit-output trap) and corrupt the run outcome.
    param(
        [Parameter(Mandatory)][string] $ScriptPath,
        [Parameter(Mandatory)][ValidateSet('Pre', 'Post')][string] $Phase,
        [Parameter(Mandatory)][object] $DomainConfig,
        [string] $Thumbprint,
        [string] $NotAfter
    )
    $domain = [string]$DomainConfig.MainDomain
    $label  = "$($Phase.ToLower())-renewal hook"

    if (-not (Test-Path -LiteralPath $ScriptPath -PathType Leaf) -or
        [System.IO.Path]::GetExtension($ScriptPath) -ne '.ps1') {
        Write-Log "Skipping $label for ${domain}: '$ScriptPath' is not an existing .ps1 file." -Level WARNING
        Write-EventLogEntry $EID.HookFailed Warning "$label skipped for ${domain}: '$ScriptPath' not found or not a .ps1"
        return 'Skipped'
    }

    if ($DryRun) {
        Write-Log "[DryRun] WOULD run $label '$ScriptPath' for $domain." -Level INFO
        return 'DryRun'
    }

    Write-Log "Running $label '$ScriptPath' for $domain..." -Level INFO
    $hookVars = [ordered]@{
        CERTRENEWAL_HOOK_PHASE      = $Phase
        CERTRENEWAL_HOOK_DOMAIN     = $domain
        CERTRENEWAL_HOOK_TYPE       = [string]$DomainConfig.Type
        CERTRENEWAL_HOOK_THUMBPRINT = [string]$Thumbprint
        CERTRENEWAL_HOOK_NOTAFTER   = [string]$NotAfter
    }
    $status = 'Ran'
    try {
        foreach ($k in $hookVars.Keys) { Set-Item -Path "Env:$k" -Value $hookVars[$k] }
        $global:LASTEXITCODE = 0
        # Capture hook stdout/stderr into a local (then DEBUG-log it) so it can never leak into this
        # function's output stream and corrupt $outcome upstream (PS implicit-output trap). Assigning the
        # invocation (rather than piping) keeps $LASTEXITCODE reliably the hook's own exit code.
        $hookOutput = & $ScriptPath 2>&1
        $exit = $LASTEXITCODE
        foreach ($line in $hookOutput) { Write-Log "  [$label] $line" -Level DEBUG }
        if ($exit) {
            $status = 'Failed'
            Write-Log "$label '$ScriptPath' for $domain exited with code $exit." -Level WARNING
            Write-EventLogEntry $EID.HookFailed Warning "$label for ${domain} exited with code $exit ('$ScriptPath')"
        }
        else {
            Write-Log "$label completed for $domain." -Level SUCCESS
        }
    }
    catch {
        $status = 'Failed'
        Write-Log "$label '$ScriptPath' for ${domain} failed: $($_.Exception.Message)" -Level WARNING
        Write-EventLogEntry $EID.HookFailed Warning "$label for ${domain} failed: $($_.Exception.Message)"
    }
    finally {
        foreach ($k in $hookVars.Keys) { Remove-Item -Path "Env:$k" -ErrorAction SilentlyContinue }
    }
    return $status
}

function Invoke-RenewalCore {
    # The ported v1 renewal loop: binding detection + config validation (incl. CertStore->Netsh
    # upgrade-on-detect), expiry check, Submit-Renewal with stale-authorization (-Force) recovery,
    # self-heal, per-Type deploy, old-cert cleanup, optional service restart, Teams failure card.
    # Never throws: per-domain failures are collected; a fatal error becomes a 'Failure' outcome
    # (exit-code policy, spec section10 - non-zero exit is reserved for config/secrets load).
    param([Parameter(Mandatory)][object] $Config, [Parameter(Mandatory)][object] $Secrets)

    $domains = @($Config.Domains)
    $renewalFailures = @()
    $renewedCount = 0
    $renewedDomains = @()
    $criticalError = $null
    $webhook = $Secrets.TeamsWebhookUrl
    # Discrete per-domain work-events (cert-renewed / service-restarted / pre-hook / post-hook), each
    # stamped when it happens; sent alongside the summary 'renew' row in one batched POST (issue #61).
    $renewalEvents = [System.Collections.Generic.List[object]]::new()

    try {
        # --- Posh-ACME environment (shared store, spec section1/section3) ---
        $env:POSHACME_HOME = if ($Config.SharedPoshAcmePath) { $Config.SharedPoshAcmePath } else { 'C:\ProgramData\Posh-ACME' }
        Write-Log "POSHACME_HOME: $env:POSHACME_HOME" -Level INFO
        Import-Module Posh-ACME -Force

        # LE_PROD unless overridden via cert-config.AcmeServer (test affordance: LE_STAGE, spec section12)
        $acmeServer = if ($Config.AcmeServer) { [string]$Config.AcmeServer } else { 'LE_PROD' }
        if ($DryRun -and (Get-PAServer)) {
            Write-Log "[DryRun] ACME server already configured: $((Get-PAServer).location) (skipping Set-PAServer $acmeServer)" -Level INFO
        }
        else {
            Set-PAServer $acmeServer
            Write-Log "ACME server: $acmeServer" -Level INFO
        }

        if ($Config.PaAccount) {
            $account = Get-PAAccount -ID $Config.PaAccount
            if (-not $account) { throw "ACME account $($Config.PaAccount) not found in shared configuration" }
            $current = Get-PAAccount
            if (-not $current -or $current.id -ne $Config.PaAccount) { Set-PAAccount -ID $Config.PaAccount }
            Write-Log "Using ACME account: $($Config.PaAccount)" -Level INFO
        }
        else {
            $account = Get-PAAccount
            if (-not $account) { throw 'No ACME account active (cert-config has no PaAccount and POSHACME_HOME has no current account)' }
            Write-Log "Using current ACME account: $($account.id)" -Level INFO
        }

        if (Get-Module -ListAvailable -Name WebAdministration) {
            Import-Module WebAdministration -ErrorAction SilentlyContinue
        }

        # --- PHASE 1: upgrade-on-detect - CertStore certs that turn out to have netsh bindings ---
        Write-Log '=== Scanning for manual netsh bindings on CertStore certificates ===' -Level INFO
        $configNeedsUpdate = $false
        foreach ($domainConfig in $domains) {
            if (-not ($domainConfig.Type -and $domainConfig.Type.ToLower() -eq 'certstore')) { continue }
            $domain = $domainConfig.MainDomain
            Write-Log "Checking CertStore certificate: $domain" -Level INFO

            $cert = Get-PACertificate -MainDomain $domain
            if (-not ($cert -and $cert.Thumbprint)) {
                Write-Log "  Certificate not found in Posh-ACME for domain: $domain" -Level WARNING
                continue
            }
            if (-not (Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Thumbprint -eq $cert.Thumbprint })) {
                Write-Log '  Certificate found in Posh-ACME but not in Windows certificate store. Skipping.' -Level WARNING
                continue
            }

            $bindingInfo = Get-NetshBindingForCertificate -Thumbprint $cert.Thumbprint
            if (-not $bindingInfo) { Write-Log '  No netsh binding found for this certificate.' -Level DEBUG; continue }
            if ([string]::IsNullOrWhiteSpace($bindingInfo.AppId)) {
                Write-Log '  Found binding(s) but AppId is missing. Cannot upgrade; manual intervention required.' -Level WARNING
                continue
            }

            $guid = $bindingInfo.AppId -replace '[{}]', ''
            try { [void][System.Guid]::Parse($guid) }
            catch {
                Write-Log "  Invalid GUID format in AppId: $($bindingInfo.AppId). Cannot upgrade." -Level WARNING
                continue
            }

            $ipPortArray = @($bindingInfo.Bindings | Where-Object { -not [string]::IsNullOrWhiteSpace($_.IpPort) } | ForEach-Object { $_.IpPort })
            if ($ipPortArray.Count -eq 0) { Write-Log '  No valid IpPort bindings found. Cannot upgrade.' -Level WARNING; continue }

            if ($DryRun) {
                Write-Log "[DryRun] WOULD upgrade $domain from CertStore to Netsh (IpPorts=$($ipPortArray -join ', '), Guid=$guid)" -Level INFO
                continue
            }

            $domainConfig.Type = 'Netsh'
            $domainConfig | Add-Member -NotePropertyName 'Guid' -NotePropertyValue $guid -Force
            $domainConfig | Add-Member -NotePropertyName 'NetshIpPorts' -NotePropertyValue $ipPortArray -Force
            if ($domainConfig.PSObject.Properties['NetshIpPort']) { $domainConfig.PSObject.Properties.Remove('NetshIpPort') }
            $configNeedsUpdate = $true
            Write-Log "  Upgraded $domain to Type=Netsh (IpPorts=$($ipPortArray -join ', '), Guid=$guid)" -Level SUCCESS
        }
        if ($configNeedsUpdate) {
            if (Save-CertConfig -Config $Config -Reason 'CertStore->Netsh upgrade') {
                # Reload so in-memory and on-disk state are identical
                try { $Config = Get-CertConfig; $domains = @($Config.Domains) }
                catch { Write-Log "Could not reload config: $($_.Exception.Message). Continuing with in-memory configuration." -Level WARNING }
            }
        }

        # --- Main renewal loop ---
        Write-Log '=== Starting certificate renewal process ===' -Level INFO
        foreach ($domainConfig in $domains) {
            $domain = $domainConfig.MainDomain
            $hasSANs = $domainConfig.SANs -and @($domainConfig.SANs).Count -gt 0
            if ($hasSANs) {
                Write-Log "--- Processing SAN certificate: $domain + $(@($domainConfig.SANs).Count) SANs ($($domainConfig.Type)) - SANs: $($domainConfig.SANs -join ', ') ---" -Level INFO
            }
            else {
                Write-Log "--- Processing: $domain ($($domainConfig.Type)) ---" -Level INFO
            }

            $cert = Get-PACertificate -MainDomain $domain

            # Self-heal: Posh-ACME lost track of the cert but config still has a thumbprint
            if (-not $cert -and $domainConfig.Thumbprint) {
                if ($DryRun) {
                    Write-Log "[DryRun] Posh-ACME has no certificate for $domain (config thumbprint $($domainConfig.Thumbprint)). WOULD self-heal via New-PACertificate -Force." -Level WARNING
                }
                else {
                    Write-Log "Posh-ACME has no certificate for $domain but config has thumbprint $($domainConfig.Thumbprint). Attempting self-heal..." -Level WARNING
                    try {
                        $sansList = @()
                        if ($domainConfig.SANs) { $sansList = @($domainConfig.SANs | Where-Object { $_ }) }
                        $null = Invoke-SelfHealCertificate -Domain $domain -SANs $sansList -OldThumbprint $domainConfig.Thumbprint -Secrets $Secrets
                        $cert = Get-PACertificate -MainDomain $domain
                        if ($cert) {
                            Write-Log 'Self-heal succeeded. Continuing with normal flow.' -Level SUCCESS
                            $renewedCount++
                            # Persist new cert details immediately so a subsequent failure before the
                            # normal config-update step still leaves a consistent state.
                            $domainConfig | Add-Member -NotePropertyName 'Thumbprint' -NotePropertyValue $cert.Thumbprint -Force
                            $domainConfig | Add-Member -NotePropertyName 'NotAfter' -NotePropertyValue ($cert.NotAfter.ToString('yyyy-MM-dd HH:mm:ss')) -Force
                            $null = Save-CertConfig -Config $Config -Reason "self-heal of $domain"
                        }
                    }
                    catch {
                        Write-Log "Self-heal failed for ${domain}: $($_.Exception.Message)" -Level ERROR
                        # $cert stays $null -> falls through to the missing-certificate failure branch
                    }
                }
            }

            if (-not $cert) {
                Write-Log "Certificate not found for $domain" -Level WARNING
                $renewalFailures += @{
                    Domain       = $domain
                    Type         = if ($domainConfig.Type) { $domainConfig.Type } else { 'Unknown' }
                    Error        = 'Certificate not found in Posh-ACME'
                    ExpiryDate   = 'N/A'
                    DaysToExpiry = 'N/A'
                }
                continue
            }

            # Detect ALL existing bindings (every run, not just when renewal is due) so manually
            # added bindings are captured and the config stays validated.
            Write-Log "Detecting existing bindings for $domain..." -Level INFO
            $detectedNetsh  = Get-ExistingNetshBindingsForDomain -Domain $domain
            $detectedIISWeb = Get-ExistingIISWebBindingsForDomain -Domain $domain
            $detectedIISFTP = Get-ExistingIISFTPBindingsForDomain -Domain $domain

            $bindingsDetected = [bool]($detectedNetsh -or $detectedIISWeb -or $detectedIISFTP)
            $detectionResults = @()
            if ($detectedNetsh)  { $detectionResults += "Netsh ($($detectedNetsh.Bindings.Count) binding(s))" }
            if ($detectedIISWeb) { $detectionResults += "IIS Web ($($detectedIISWeb.Bindings.Count) binding(s))" }
            if ($detectedIISFTP) { $detectionResults += "IIS FTP ($($detectedIISFTP.Bindings.Count) site(s))" }
            if ($bindingsDetected) { Write-Log "Detected bindings: $($detectionResults -join ', ')" -Level INFO }
            else { Write-Log "No existing bindings detected. Configured Type: $($domainConfig.Type)" -Level INFO }

            # Validate config against reality (cert details + Type)
            $configNeedsUpdate = $false
            $currentThumbprint = $cert.Thumbprint
            $currentNotAfter   = $cert.NotAfter.ToString('yyyy-MM-dd HH:mm:ss')
            if ($domainConfig.Thumbprint -ne $currentThumbprint -or $domainConfig.NotAfter -ne $currentNotAfter) {
                if ($DryRun) {
                    Write-Log "[DryRun] WOULD update config cert details for $domain (thumbprint $currentThumbprint, expires $currentNotAfter)." -Level INFO
                }
                else {
                    Write-Log "Updating certificate details in config: thumbprint=$currentThumbprint, expires=$currentNotAfter" -Level INFO
                    $domainConfig | Add-Member -NotePropertyName 'Thumbprint' -NotePropertyValue $currentThumbprint -Force
                    $domainConfig | Add-Member -NotePropertyName 'NotAfter' -NotePropertyValue $currentNotAfter -Force
                    $configNeedsUpdate = $true
                }
            }

            $correctType =
                if (-not $bindingsDetected) { 'CertStore' }
                elseif ($detectedNetsh -and -not $detectedIISWeb -and -not $detectedIISFTP) { 'Netsh' }
                elseif ($detectedIISWeb -and -not $detectedNetsh -and -not $detectedIISFTP) { 'IIS Web' }
                elseif ($detectedIISFTP -and -not $detectedNetsh -and -not $detectedIISWeb) { 'IIS FTP' }
                elseif ($domainConfig.Type -eq 'Netsh' -and $detectedIISWeb -and $detectedNetsh -and
                        (Test-IsIISWebAppId -AppId $detectedNetsh.AppId)) {
                    # Self-heal (issue #49): a no-SNI IIS Web binding (sslFlags=0) is stored by http.sys
                    # at 0.0.0.0:443 under IIS's own appid, so it surfaces as BOTH Netsh and IIS Web. The
                    # v1 creator could capture that as Type=Netsh; flip it to IIS Web here (the one path
                    # that reaches every fleet box) so the IIS surface stays authoritative and a future
                    # fallback deploy never re-pushes a stale thumbprint via netsh. The IIS appid on the
                    # netsh binding is the discriminator - a genuine non-IIS netsh binding (custom appid)
                    # coexisting with an IIS site falls through to the preserve branch below.
                    Write-Log "Netsh binding is IIS-owned (appid $($detectedNetsh.AppId)) and an IIS Web binding exists for the same cert. Reclassifying Type=Netsh -> IIS Web (issue #49)." -Level WARNING
                    'IIS Web'
                }
                else {
                    # Multiple binding types detected - keep the configured Type but still update
                    # all detected bindings after a renewal.
                    Write-Log "Multiple binding types detected. Config Type remains: $($domainConfig.Type)" -Level WARNING
                    $domainConfig.Type
                }

            if ($correctType -and $correctType -ne $domainConfig.Type) {
                if ($DryRun) {
                    Write-Log "[DryRun] Config mismatch: Type=$($domainConfig.Type) but detected $correctType. WOULD update configuration." -Level INFO
                }
                else {
                    Write-Log "Config mismatch: Type=$($domainConfig.Type) but detected $correctType. Updating configuration." -Level WARNING
                    $domainConfig.Type = $correctType
                    if ($correctType -eq 'Netsh' -and $detectedNetsh) {
                        # Store the GUID brace-stripped so the Netsh fallback deploy (appid="{guid}")
                        # never double-wraps it (v1 stored the raw {guid} here).
                        $ipPorts = @($detectedNetsh.Bindings | ForEach-Object { $_.IpPort })
                        $domainConfig | Add-Member -NotePropertyName 'Guid' -NotePropertyValue ($detectedNetsh.AppId -replace '[{}]', '') -Force
                        $domainConfig | Add-Member -NotePropertyName 'NetshIpPorts' -NotePropertyValue $ipPorts -Force
                        if ($domainConfig.PSObject.Properties['NetshIpPort']) { $domainConfig.PSObject.Properties.Remove('NetshIpPort') }
                        Write-Log "  Netsh config: GUID=$($domainConfig.Guid), IpPorts=$($ipPorts -join ', ')" -Level INFO
                    }
                    if ($correctType -eq 'IIS FTP' -and $detectedIISFTP) {
                        $ftpSiteName = ($detectedIISFTP.Bindings | Select-Object -First 1).SiteName
                        $domainConfig | Add-Member -NotePropertyName 'Guid' -NotePropertyValue $ftpSiteName -Force
                        Write-Log "  FTP site name: $ftpSiteName" -Level INFO
                    }
                    if ($correctType -eq 'IIS Web') {
                        # IIS manages its own binding by site name; drop any stale Netsh Guid/IpPorts so a
                        # future fallback deploy can't re-push via netsh (issue #49 self-heal target).
                        foreach ($p in 'Guid', 'NetshIpPorts', 'NetshIpPort') {
                            if ($domainConfig.PSObject.Properties[$p]) { $domainConfig.PSObject.Properties.Remove($p) }
                        }
                        Write-Log '  IIS Web binding is authoritative; dropped any stale Netsh Guid/IpPorts.' -Level INFO
                    }
                    if ($correctType -eq 'CertStore') {
                        foreach ($p in 'Guid', 'NetshIpPorts', 'NetshIpPort') {
                            if ($domainConfig.PSObject.Properties[$p]) { $domainConfig.PSObject.Properties.Remove($p) }
                        }
                        Write-Log '  Certificate is no longer bound to any service.' -Level INFO
                    }
                    $configNeedsUpdate = $true
                }
            }
            else { Write-Log "Configuration is up-to-date (Type: $($domainConfig.Type))" -Level DEBUG }

            if ($configNeedsUpdate) { $null = Save-CertConfig -Config $Config -Reason "binding validation for $domain" }

            # --- Expiry check + renewal ---
            $expiryDate = $cert.NotAfter
            $daysToExpiry = ($expiryDate - (Get-Date)).Days
            # Per-domain renewal lead time (config.RenewalThresholdDays), else the script default. Tolerant
            # of a hand-edited config: a non-numeric / <=0 value falls back to the default with a warning.
            $threshold = $RenewalThresholdDays
            if ($domainConfig.PSObject.Properties['RenewalThresholdDays']) {
                $parsedThreshold = 0
                if ([int]::TryParse([string]$domainConfig.RenewalThresholdDays, [ref]$parsedThreshold) -and $parsedThreshold -gt 0) {
                    $threshold = $parsedThreshold
                }
                else {
                    Write-Log "Ignoring invalid RenewalThresholdDays '$($domainConfig.RenewalThresholdDays)' for $domain; using default $RenewalThresholdDays." -Level WARNING
                }
            }
            Write-Log "Certificate expires $expiryDate ($daysToExpiry days; renew at <= $threshold days)" -Level INFO

            if (-not $Force -and $daysToExpiry -gt $threshold) {
                Write-Log "Certificate for $domain is still valid ($daysToExpiry days remaining). No renewal needed." -Level INFO
                continue
            }
            if ($Force -and $daysToExpiry -gt $threshold) {
                Write-Log "Force: renewing $domain now despite $daysToExpiry days remaining (threshold $threshold)." -Level WARNING
            }

            if ($DryRun) {
                $deployVia = if ($bindingsDetected) { "detected: $($detectionResults -join ', ')" } else { "config Type $($domainConfig.Type)" }
                $forcedNote = if ($Force) { ' [forced]' } else { '' }
                Write-Log "[DryRun] WOULD renew $domain (expires in $daysToExpiry days)$forcedNote and update bindings ($deployVia)." -Level INFO
                if ($domainConfig.PSObject.Properties['PreRenewalScript'] -and $domainConfig.PreRenewalScript) {
                    Write-Log "[DryRun] WOULD run pre-renewal hook '$($domainConfig.PreRenewalScript)' for $domain." -Level INFO
                }
                if ($domainConfig.PSObject.Properties['PostRenewalScript'] -and $domainConfig.PostRenewalScript) {
                    Write-Log "[DryRun] WOULD run post-renewal hook '$($domainConfig.PostRenewalScript)' for $domain." -Level INFO
                }
                continue
            }

            if (-not ($Force -and $daysToExpiry -gt $threshold)) {
                Write-Log "Certificate expires in $threshold days or less. Initiating renewal..." -Level WARNING
            }
            # Pre-renewal hook (config.PreRenewalScript) - best-effort; a failure never blocks the renewal.
            if ($domainConfig.PSObject.Properties['PreRenewalScript'] -and $domainConfig.PreRenewalScript) {
                $hookStatus = Invoke-RenewalHook -ScriptPath $domainConfig.PreRenewalScript -Phase Pre -DomainConfig $domainConfig `
                    -Thumbprint $cert.Thumbprint -NotAfter ($cert.NotAfter.ToString('yyyy-MM-dd HH:mm:ss'))
                $renewalEvents.Add((New-TelemetryEvent -Action 'pre-hook' -Domain $domain -RunOutcome $hookStatus -Message ([string]$domainConfig.PreRenewalScript)))
            }
            # Heal a v1-migrated order whose DnsVariant was serialized empty by an older Posh-ACME: the newer
            # module's Submit-Renewal/New-PACertificate reject '' (ValidateSet dns-01,dns-account-01) and the
            # renewal would otherwise fail (issue #59). Best-effort, version-guarded (no-op on a module
            # without DnsVariant), idempotent (only acts when empty).
            try {
                $paOrder = Get-PAOrder -MainDomain $domain -ErrorAction SilentlyContinue
                if ($paOrder -and $paOrder.PSObject.Properties['DnsVariant'] -and
                    [string]::IsNullOrWhiteSpace([string]$paOrder.DnsVariant) -and
                    (Get-Command Set-PAOrder -ErrorAction SilentlyContinue).Parameters.ContainsKey('DnsVariant')) {
                    Write-Log "Healing empty DnsVariant on the saved order for $domain (-> dns-01)." -Level INFO
                    Set-PAOrder -MainDomain $domain -DnsVariant 'dns-01' -ErrorAction Stop
                }
            }
            catch { Write-Log "Could not heal DnsVariant for ${domain}: $($_.Exception.Message)" -Level WARNING }
            try {
                # Submit renewal with retry. The script -Force forwards to Submit-Renewal -Force so the
                # cert is re-issued even when ARI says it is not in the renewal window yet (genuine forced
                # rotation, not just bypassing our local threshold). If the ACME server has pruned stale
                # authorizations for the existing order (common when ARI signals "renew AS SOON AS
                # POSSIBLE"), Submit-Renewal fails with "Cannot bind argument to parameter 'AuthURLs'
                # because it is null." Recover by retrying with -Force, which forwards to New-PACertificate
                # -Force and creates a fresh order with new authorizations while preserving stored plugin
                # args and DnsAlias.
                Invoke-WithRetry -OperationName "Certificate renewal for $domain" -MaxRetries 3 -InitialDelaySeconds 10 -ScriptBlock {
                    try { Submit-Renewal -MainDomain $domain -Force:$Force }
                    catch {
                        if ($_.Exception.Message -match 'AuthURLs|Authorization not found|No such authorization') {
                            Write-Log "Stale authorization state detected for $domain. Retrying with -Force to create a fresh order..." -Level WARNING
                            Submit-Renewal -MainDomain $domain -Force
                        }
                        else { throw }
                    }
                } | Out-Null
                Write-Log 'Renewal completed successfully.' -Level SUCCESS

                $newCert = Get-PACertificate -MainDomain $domain
                Write-Log 'Installing renewed certificate...' -Level INFO
                Install-PACertificate -PACertificate $newCert -StoreLocation LocalMachine -StoreName My
                Write-Log 'Certificate installed to LocalMachine\My.' -Level SUCCESS
                $renewedCount++
                $renewedDomains += $domain
                $forcedNote = if ($Force) { ', forced' } else { '' }
                $renewalEvents.Add((New-TelemetryEvent -Action 'cert-renewed' -Domain $domain -RunOutcome 'Renewed' `
                    -Message ("{0} -> {1} ({2}d to expiry{3})" -f $cert.Thumbprint, $newCert.Thumbprint, $daysToExpiry, $forcedNote)))

                $bindingSuccess = $false

                # Update all DETECTED bindings first
                try {
                    $anyBindingUpdated = $false
                    if ($detectedNetsh) {
                        Write-Log 'Updating detected Netsh HTTP.SYS binding(s)...' -Level INFO
                        foreach ($b in $detectedNetsh.Bindings) {
                            if (Update-NetshBinding -IpPort $b.IpPort -BindingKey $b.BindingKey -AppId $b.AppId -Thumbprint $newCert.Thumbprint) { $anyBindingUpdated = $true }
                        }
                    }
                    if ($detectedIISWeb) {
                        Write-Log 'Updating detected IIS Web binding(s)...' -Level INFO
                        foreach ($b in $detectedIISWeb.Bindings) {
                            if (Update-IISWebBinding -SiteName $b.SiteName -BindingInformation $b.BindingInformation -Thumbprint $newCert.Thumbprint) { $anyBindingUpdated = $true }
                        }
                    }
                    if ($detectedIISFTP) {
                        Write-Log 'Updating detected IIS FTP binding(s)...' -Level INFO
                        foreach ($b in $detectedIISFTP.Bindings) {
                            if (Update-IISFTPBinding -SiteName $b.SiteName -Thumbprint $newCert.Thumbprint) { $anyBindingUpdated = $true }
                        }
                    }
                    if ($anyBindingUpdated) {
                        $bindingSuccess = $true
                        Write-Log 'All detected bindings updated.' -Level SUCCESS
                    }
                }
                catch { Write-Log "Error updating detected bindings: $($_.Exception.Message)" -Level WARNING }

                # FALLBACK: no bindings detected -> deploy per configured Type (initial deployments)
                if (-not $bindingsDetected) {
                    Write-Log "Using configured deployment type: $($domainConfig.Type)" -Level INFO
                    $bindingSuccess = Deploy-Certificate -DomainConfig $domainConfig -NewCert $newCert
                }

                # Only clean up old certificates if the binding update succeeded
                if ($bindingSuccess) {
                    Write-Log 'Binding update successful. Proceeding with certificate cleanup...' -Level INFO
                    $escapedDomain = [regex]::Escape($domain)
                    $allCertsForDomain = @(Get-ChildItem Cert:\LocalMachine\My | Where-Object {
                        ($_.Subject -match "CN\s*=\s*$escapedDomain\b") -or ($_.DnsNameList.Unicode -contains $domain)
                    })
                    Write-Log "Found $($allCertsForDomain.Count) certificate(s) for $domain" -Level DEBUG
                    foreach ($oldCert in $allCertsForDomain) {
                        if ($oldCert.Thumbprint -eq $newCert.Thumbprint) { continue }
                        $oldDays = ($oldCert.NotAfter - (Get-Date)).Days
                        try {
                            if ($oldDays -le $threshold) {
                                Write-Log "Removing old certificate $($oldCert.Thumbprint) (expires $($oldCert.NotAfter), $oldDays days)" -Level INFO
                                Remove-Item -Path "Cert:\LocalMachine\My\$($oldCert.Thumbprint)" -Force -ErrorAction Stop
                            }
                            else {
                                Write-Log "Keeping valid certificate $($oldCert.Thumbprint) (expires $($oldCert.NotAfter), $oldDays days)" -Level DEBUG
                            }
                        }
                        catch {
                            Write-Log "Failed to remove certificate $($oldCert.Thumbprint): $($_.Exception.Message) (may still be in use by another service)" -Level WARNING
                        }
                    }
                }
                else {
                    Write-Log 'Binding update failed or could not be verified. Keeping all certificates for safety; manual intervention may be required.' -Level WARNING
                }

                Write-Log "Renewal process completed for $domain" -Level SUCCESS

                # Optional service restart (config.RestartService)
                if ($domainConfig.PSObject.Properties['RestartService'] -and $domainConfig.RestartService) {
                    $serviceName = $domainConfig.RestartService
                    $svcStatus = 'Ok'
                    Write-Log "Restarting Windows service: $serviceName..." -Level INFO
                    try {
                        $svc = Get-Service -Name $serviceName -ErrorAction Stop
                        Write-Log "  Service found: $($svc.DisplayName) (Status: $($svc.Status))" -Level DEBUG
                        Restart-Service -Name $serviceName -Force -ErrorAction Stop
                        $svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
                        if ($svc.Status -eq 'Running') {
                            Write-Log "Service '$serviceName' restarted after renewal of $domain (Status: Running)" -Level SUCCESS
                        }
                        else {
                            $svcStatus = 'Unexpected'
                            Write-Log "Service '$serviceName' restarted but status is $($svc.Status) after renewal of $domain" -Level WARNING
                        }
                    }
                    catch { $svcStatus = 'Failed'; Write-Log "Failed to restart service '$serviceName' after renewal of ${domain}: $($_.Exception.Message)" -Level ERROR }
                    $renewalEvents.Add((New-TelemetryEvent -Action 'service-restarted' -Domain $domain -RunOutcome $svcStatus -Message ([string]$serviceName)))
                }

                # Optional post-renewal hook (config.PostRenewalScript) - best-effort; runs after a
                # successful renew + deploy, with the NEW thumbprint/expiry in the environment.
                if ($domainConfig.PSObject.Properties['PostRenewalScript'] -and $domainConfig.PostRenewalScript) {
                    $hookStatus = Invoke-RenewalHook -ScriptPath $domainConfig.PostRenewalScript -Phase Post -DomainConfig $domainConfig `
                        -Thumbprint $newCert.Thumbprint -NotAfter ($newCert.NotAfter.ToString('yyyy-MM-dd HH:mm:ss'))
                    $renewalEvents.Add((New-TelemetryEvent -Action 'post-hook' -Domain $domain -RunOutcome $hookStatus -Message ([string]$domainConfig.PostRenewalScript)))
                }

                # Persist new certificate details
                $domainConfig | Add-Member -NotePropertyName 'Thumbprint' -NotePropertyValue $newCert.Thumbprint -Force
                $domainConfig | Add-Member -NotePropertyName 'NotAfter' -NotePropertyValue ($newCert.NotAfter.ToString('yyyy-MM-dd HH:mm:ss')) -Force
                $null = Save-CertConfig -Config $Config -Reason "renewal of $domain"
            }
            catch {
                $errorMsg = $_.Exception.Message
                Write-Log "Failed to renew certificate for ${domain}: $errorMsg" -Level ERROR
                $renewalFailures += @{
                    Domain       = $domain
                    Type         = $domainConfig.Type
                    Error        = $errorMsg
                    ExpiryDate   = $expiryDate
                    DaysToExpiry = $daysToExpiry
                }
            }
        }   # foreach domain

        # Teams failure card - failures only, no heartbeat (spec section7)
        if ($renewalFailures.Count -gt 0) {
            Write-Log "=== $($renewalFailures.Count) renewal failure(s) detected - sending Teams notification ===" -Level ERROR
            $failureMessage = (@($renewalFailures | ForEach-Object { "- **$($_.Domain)** ($($_.Type)): $($_.Error)" }) -join "`n`n")
            $facts = Get-TeamsFacts -Config $Config
            $facts['Failed Certificates'] = $renewalFailures.Count
            Send-TeamsNotification -WebhookUrl $webhook -Title 'Certificate Renewal Failed' `
                -Message $failureMessage -Severity attention -Facts $facts
        }
        Write-Log 'All renewal checks completed.' -Level INFO
    }
    catch {
        # Fatal error inside the renewal core (e.g. Posh-ACME missing, account not found).
        # Exit-code policy (spec section10): report via Teams + outcome, do NOT propagate to main.
        $criticalError = $_.Exception.Message
        Write-Log "Critical failure during renewal: $criticalError" -Level ERROR
        Write-Log "Stack trace: $($_.ScriptStackTrace)" -Level DEBUG
        $facts = Get-TeamsFacts -Config $Config
        $facts['Error Type'] = 'Critical Failure'
        Send-TeamsNotification -WebhookUrl $webhook -Title 'Certificate Renewal Script - Critical Failure' `
            -Message "The renewal script encountered a critical error and stopped execution.`n`n**Error:** $criticalError" `
            -Severity attention -Facts $facts
        $renewalFailures += @{ Domain = '(run)'; Type = 'Critical'; Error = $criticalError; ExpiryDate = 'N/A'; DaysToExpiry = 'N/A' }
    }

    # Outcome for telemetry (liveness/inventory/billing payload, spec section7 + telemetry section2) +
    # Event Log in main. Tracks the soonest expiry (+ its domain) and per-cert detail.
    $nextExpiry = $null; $nextExpiryDomain = $null
    foreach ($d in $domains) {
        if ($d.NotAfter) {
            try {
                $dt = [datetime]$d.NotAfter
                if (-not $nextExpiry -or $dt -lt $nextExpiry) { $nextExpiry = $dt; $nextExpiryDomain = $d.MainDomain }
            }
            catch { }
        }
    }
    $failedDomains = @($renewalFailures | ForEach-Object { $_.Domain })
    $certificates = @(foreach ($d in $domains) {
        [ordered]@{
            domain     = [string]$d.MainDomain
            thumbprint = [string]$d.Thumbprint
            notAfter   = if ($d.NotAfter) { [string]$d.NotAfter } else { $null }
            outcome    = if ($failedDomains -contains $d.MainDomain) { 'Failed' }
                         elseif ($renewedDomains -contains $d.MainDomain) { 'Renewed' }
                         else { 'Valid' }
        }
    })
    $runOutcome =
        if ($DryRun) { 'DryRun' }
        elseif ($renewalFailures.Count -eq 0) { 'Success' }
        elseif ($domains.Count -gt 0 -and $renewalFailures.Count -lt $domains.Count) { 'PartialFailure' }
        else { 'Failure' }
    $message =
        if ($criticalError) { "Critical failure: $criticalError" }
        elseif ($renewalFailures.Count -gt 0) { "$($renewalFailures.Count) of $($domains.Count) renewal(s) failed: $($failedDomains -join ', ')" }
        elseif ($renewedCount -gt 0) { "Renewed $renewedCount of $($domains.Count) certificate(s)." }
        else { "No renewals due ($($domains.Count) certificate(s) checked)." }
    return [pscustomobject]@{
        RunOutcome       = $runOutcome
        CertCount        = $domains.Count
        Renewed          = $renewedCount
        Failures         = @($renewalFailures)
        NextExpiry       = if ($nextExpiry) { $nextExpiry.ToString('yyyy-MM-dd HH:mm:ss') } else { $null }
        NextExpiryDomain = $nextExpiryDomain
        Certificates     = $certificates
        Message          = $message
        RenewalEvents    = @($renewalEvents)   # discrete work-events, sent with the summary in one POST
    }
}

#endregion Renewal core ---------------------------------------------------------

#region Main ------------------------------------------------------------------

# Log dir + transcript rotation (keep 90 days)
try {
    if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
    Get-ChildItem $LogDir -Filter 'cert-renew-*.log' -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-90) } | Remove-Item -Force -ErrorAction SilentlyContinue
}
catch { }

$transcriptPath = Join-Path $LogDir ("cert-renew-{0}.log" -f (Get-Date -Format 'yyyy-MM-dd-HH_mm_ss'))
try { Start-Transcript -Path $transcriptPath -Append | Out-Null } catch { }

$exitCode = 0
try {
    Write-Log "=== Renew-Cert v$ScriptVersion starting (DryRun=$DryRun, CheckOnly=$CheckOnly, SkipSelfUpdate=$SkipSelfUpdate, Force=$Force) ===" -Level INFO
    Write-EventLogEntry $EID.Start Information "Renew-Cert v$ScriptVersion starting"

    $config = Get-CertConfig

    if ($CheckOnly) {
        $domains = @($config.Domains)
        Write-Log "CheckOnly: version=$ScriptVersion schema=$($config.SchemaVersion) certs=$($domains.Count)" -Level INFO
        foreach ($d in $domains) {
            $sans = if ($d.SANs) { " + SANs: $($d.SANs -join ', ')" } else { '' }
            Write-Log "  $($d.MainDomain) [$($d.Type)]$sans" -Level INFO
        }
        Write-Log 'CheckOnly complete.' -Level SUCCESS
    }
    else {
        Update-SecretsFromVault -Config $config   # D2: best-effort rotation refresh before reading secrets
        $secrets = Get-Secrets   # fail closed if missing

        if (-not $SkipSelfUpdate) {
            if (Invoke-SelfUpdate -Config $config) {
                Write-Log 'Exiting after self-update; the new version runs on the next schedule.' -Level INFO
                try { Stop-Transcript | Out-Null } catch { }
                exit 0
            }
        }
        else { Write-Log 'Self-update skipped (-SkipSelfUpdate).' -Level INFO; $SelfUpdateStatus = 'Skipped' }

        $outcome = Invoke-RenewalCore -Config $config -Secrets $secrets

        if ($outcome.RunOutcome -eq 'Success') { Write-EventLogEntry $EID.RenewSuccess Information 'Renewal run succeeded' }
        elseif ($outcome.Failures.Count -gt 0)  { Write-EventLogEntry $EID.RenewFailure Error "Renewal run had $($outcome.Failures.Count) failure(s)" }

        # Best-effort liveness/inventory/billing event (the 'renew' summary) + the discrete per-domain
        # work-events, all in one batched POST. The summary defaults Action='renew' and carries no Domain.
        Send-Telemetry -Config $config -Outcome (@($outcome) + @($outcome.RenewalEvents))

        # Exit-code policy (spec section10): 0 even on partial/total renewal failure - Teams + telemetry are the signal.
        Write-Log "=== Renew-Cert finished (outcome=$($outcome.RunOutcome)) ===" -Level SUCCESS
    }
}
catch {
    # Fatal startup failure only (config/secrets load) reaches here.
    Write-Log "FATAL: $($_.Exception.Message)" -Level ERROR
    Write-EventLogEntry $EID.RenewFailure Error "Fatal startup failure: $($_.Exception.Message)"
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
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCA1Llbaj/47iYVw
# T0dFvqnWjMBhhKGNZ7EJ27oxxL7wAaCCF6gwggRqMIIC0qADAgECAhA9a+7a4tnR
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
# gjcCARUwLwYJKoZIhvcNAQkEMSIEIB9N+4HbUfe0yeGfbBw6nXtrdi6fKrG/w5GH
# f5TzLJTvMA0GCSqGSIb3DQEBAQUABIIBgJZ91ZTPxRUn/Qh41N6+3LVItUQS1Kuy
# 77q7y7csJY+YLx7g/r+OdS8ROmo7NmA/Wq43TXx7oTZAlYmQ46+zCHUUN0iqybLG
# 7B/WrWOiJyfhB/xEMrdGdDFjgj72h7UDMFyKRm6envdp0YdmrqSAtBtESx0+YGCZ
# LJHjq3ARPs4mTiDmLfetk4Yf25usI1+6cjAGoDymRWQ3GljNMc+iNnl/S+0Hywza
# G4LttqRAS4twNfWnNzUyRLAJw8p2fmtRwVgkCQE9Y9sAeNaRxUUQDg472M/lHYC0
# NmTcVTbG6U7Xl+DdHGi7zJF9Z9mtILjpPHxlVMUwOl49DsuGJvcyqiVAh6l4IpXU
# dWeWUZOZ4qlgDVPEuHXIJKL6J8p7GthNvPkwoEKHmYaRXtJ3awlmMCdZgoMPiPaS
# wpo/xKcuig17mr5MLoy89RZbhjCnLu1/4T6oMoYnytc5pJOuu71MCs6BNk9gj6kg
# 4fOaf4bLhIeh86lQT00m2fVb0qcxylrE76GCAyYwggMiBgkqhkiG9w0BCQYxggMT
# MIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5j
# LjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNB
# NDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZIAWUD
# BAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEP
# Fw0yNjA2MjQxMDMzNTVaMC8GCSqGSIb3DQEJBDEiBCDEmPqwybBTSwA7sjMBCY7u
# WQszitiDDNxfbdj5PZvmgzANBgkqhkiG9w0BAQEFAASCAgAOmhBCGoIkdre0ha7W
# T8MfGzP7GBxhPOYcjKJLGk2e2lg0qkcioU63N09M/ryo4HiobxtR0ybCNn5QnFrj
# 68eeJ7AxZFmT49ryoOUk3kd140YTY87P3W8cLMpsI+qdpjcNJxHQXqvon0o5RQil
# sgc1T9tc9gzbBBrL4pZb2W2aMhoDWurLD1Twd0KZi1f+DJ134N5HWQfSiOSFnm91
# CNzXvtVlo5cW6dEuTAgzETddsR0kwccoibpSEB3LF/Gmkcbw5wEPCoa9Dmounj/F
# ism5KfELEGgN3MxuIEHJxVczeXbWZ4NtZfQSDHahI9YgoWQrsg675BrMEfBP1ACx
# bJFtmZW4UFes/WuZnMrlIOU543Jcm+77Iei3rpEa6fUiuBeG6cU7+Vcrgl0RDVz9
# phx+HIIzpeoVk9rj7MVU2MZtFHGAZOyjxSmrLDW+M0fkk0MlZlS/c7RgVn5rI7Bo
# IaQOpUkv7CTXDE7ZLGl/nsDZuZjcIYvAkCAacO/Wa8kVZ9OUmq5sXGqb2EoQGD1v
# pzYxUzs+QFGuFtUDvdDPNWHZGgBQQEzYZkQzyEG5ZmwOonKBz7wlJRJY/P6BgdcF
# akl689ME9IXugSip5knBLVwgcTpLrdL6sULWBZ3uG1w4vDCuXFrOh5qFFWAntgi1
# bfyLV8RlLkbhlC09FxO26M18vw==
# SIG # End signature block
