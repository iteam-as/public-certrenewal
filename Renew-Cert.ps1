#Requires -Version 5.1
<#
.SYNOPSIS
  Renewal script for cert-renewal v2. Runs daily as NT AUTHORITY\SYSTEM via Scheduled Task.
.DESCRIPTION
  v2 plumbing (PR A): load cert-config.json, load + DPAPI-LM decrypt cert-secrets.json,
  self-update from the manifest (sha256 + Authenticode thumbprint gate + circuit-breaker +
  PinVersion), local logging (transcript + Windows Event Log), a Teams failure card, and a
  Send-Telemetry stub. Renewal core (PR B, ported from v1): per-domain binding detection
  (netsh / IIS Web / IIS FTP) + config validation incl. the automatic CertStore->Netsh upgrade,
  Submit-Renewal with stale-authorization (-Force) recovery, self-heal via New-PACertificate
  when Posh-ACME has lost track of an order, per-Type deploy, old-cert cleanup, optional
  service restart (see docs/phase1-renew-cert-spec.md section9). Domeneshop creds (self-heal only) and
  the Teams webhook come from cert-secrets.json. No periodic Teams heartbeat - the per-run
  telemetry event to Log Analytics is the liveness signal (docs/telemetry-log-analytics-setup.md).
.PARAMETER DryRun
  Read-only: log what WOULD happen; no self-update replace, no renew/deploy, no Teams/telemetry POST.
.PARAMETER ManifestUrl
  Override the manifest URL (test channel). Else cert-config.ManifestUrl, else the built-in prod URL.
.PARAMETER SkipSelfUpdate
  Skip the self-update check (isolate renewal logic in tests).
.PARAMETER CheckOnly
  Print version + certificate inventory and exit (ad-hoc audit). Skips secrets, self-update, renewal.
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
    [switch] $CheckOnly
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue   # for DPAPI ProtectedData

# CI replaces 'DEV' with the release tag (e.g. 2.0.0) at publish time.
$ScriptVersion = '0.0.2-test'

# Self-signed code-signing thumbprints trusted for self-updates (array = rotation overlap).
# Enforced by THIS running script before any atomic replace; never relax via config/manifest.
# See docs/code-signing.md.
$AllowedSignerThumbprints = @(
    '96705BBE468876FC2E48D27F3E7827500CF636E5'   # Iteam AS Cert-Renewal Code Signing (2026-06-04 .. 2036)
)

# Built-in production manifest URL (overridable via -ManifestUrl or cert-config.ManifestUrl test channel).
$DefaultManifestUrl = 'https://raw.githubusercontent.com/iteam-as/public-certrenewal/main/manifest.json'

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
$EID = @{ Start = 1000; UpToDate = 1001; Upgraded = 1010; RenewSuccess = 1020; RenewFailure = 1030; SigRefused = 1040; Breaker = 1050 }

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

function Send-Telemetry {
    # Phase-1 STUB. The real Logs Ingestion API POST (client-cert assertion -> DCR) lands in the
    # telemetry phase; see docs/telemetry-log-analytics-setup.md. This per-run event is the liveness signal.
    param([object] $Config, [object] $Outcome)
    if ($DryRun) { Write-Log '[DryRun] WOULD emit telemetry event.' -Level INFO; return }
    Write-Log ("[telemetry stub] event: server={0} version={1} outcome={2} certs={3} renewed={4} nextExpiry={5}" -f `
        $env:COMPUTERNAME, $ScriptVersion, $Outcome.RunOutcome, $Outcome.CertCount, $Outcome.Renewed, $Outcome.NextExpiry) -Level DEBUG
}

function Invoke-SelfUpdate {
    # Returns $true if the script replaced itself (caller should exit 0 so next run uses the new version).
    param([Parameter(Mandatory)][object] $Config)

    if (-not $SelfPath) { Write-Log 'Cannot resolve own path ($PSCommandPath empty); skipping self-update.' -Level WARNING; return $false }

    $url = if ($ManifestUrl) { $ManifestUrl } elseif ($Config.ManifestUrl) { $Config.ManifestUrl } else { $DefaultManifestUrl }

    if ($Config.PinVersion) {
        Write-Log "PinVersion=$($Config.PinVersion) set in cert-config - skipping self-update." -Level INFO
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
            return $false
        }

        if ($DryRun) { Write-Log "[DryRun] WOULD upgrade $ScriptVersion -> $latest from $($manifest.renewal.url)" -Level INFO; return $false }

        # The download target MUST keep a .ps1 extension: Get-AuthenticodeSignature resolves
        # its signature parser (SIP) from the extension, so a '.new' file always reads as
        # "not signed" and the gate would refuse every update (caught by the section-12 lab).
        $newPath = Join-Path (Split-Path $SelfPath -Parent) ([IO.Path]::GetFileNameWithoutExtension($SelfPath) + '.new.ps1')
        Write-Log "Downloading renewal $latest from $($manifest.renewal.url)" -Level INFO
        Invoke-WithRetry -OperationName 'script download' -ScriptBlock { Invoke-WebRequest -Uri $manifest.renewal.url -OutFile $newPath -TimeoutSec 30 -UseBasicParsing } | Out-Null

        $hash = (Get-FileHash $newPath -Algorithm SHA256).Hash.ToLower()
        if ($hash -ne ([string]$manifest.renewal.sha256).ToLower()) {
            Remove-Item $newPath -Force -ErrorAction SilentlyContinue
            throw "sha256 mismatch (downloaded $hash, manifest $($manifest.renewal.sha256))"
        }

        $auth = Test-AuthenticodeAllowed -FilePath $newPath
        if (-not $auth.Allowed) {
            Remove-Item $newPath -Force -ErrorAction SilentlyContinue
            Write-EventLogEntry $EID.SigRefused Error "Self-update signature refused: $($auth.Reason)"
            throw "signature refused ($($auth.Reason))"
        }

        Move-Item -Path $newPath -Destination $SelfPath -Force   # atomic on NTFS
        Write-Log "Upgraded renewal script $ScriptVersion -> $latest (signer $($auth.Thumbprint)). Next run executes the new version." -Level SUCCESS
        Write-EventLogEntry $EID.Upgraded Information "Upgraded $ScriptVersion -> $latest"
        $state.consecutiveFailures = 0; Save-SelfUpdateState $state
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
        $bindings = Get-IISWebBindingsForThumbprint -Thumbprint $cert.Thumbprint
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
        $bindings = Get-IISFTPBindingsForThumbprint -Thumbprint $cert.Thumbprint
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
            $oldIISWebBindings = Get-IISWebBindingsForThumbprint -Thumbprint $OldThumbprint
            if ($oldIISWebBindings.Count -gt 0) { Write-Log "  Captured $($oldIISWebBindings.Count) IIS Web binding(s) against old thumbprint" -Level INFO }
            $oldIISFTPBindings = Get-IISFTPBindingsForThumbprint -Thumbprint $OldThumbprint
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
    $webhook = $Secrets.TeamsWebhookUrl

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
            Write-Log "Certificate expires $expiryDate ($daysToExpiry days)" -Level INFO

            if ($daysToExpiry -gt 30) {
                Write-Log "Certificate for $domain is still valid ($daysToExpiry days remaining). No renewal needed." -Level INFO
                continue
            }

            if ($DryRun) {
                $deployVia = if ($bindingsDetected) { "detected: $($detectionResults -join ', ')" } else { "config Type $($domainConfig.Type)" }
                Write-Log "[DryRun] WOULD renew $domain (expires in $daysToExpiry days) and update bindings ($deployVia)." -Level INFO
                continue
            }

            Write-Log 'Certificate expires in 30 days or less. Initiating renewal...' -Level WARNING
            try {
                # Submit renewal with retry. If the ACME server has pruned stale authorizations for
                # the existing order (common when ARI signals "renew AS SOON AS POSSIBLE"),
                # Submit-Renewal fails with "Cannot bind argument to parameter 'AuthURLs' because it
                # is null." Recover by retrying with -Force, which forwards to New-PACertificate
                # -Force and creates a fresh order with new authorizations while preserving stored
                # plugin args and DnsAlias.
                Invoke-WithRetry -OperationName "Certificate renewal for $domain" -MaxRetries 3 -InitialDelaySeconds 10 -ScriptBlock {
                    try { Submit-Renewal -MainDomain $domain }
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
                            if ($oldDays -le 30) {
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
                            Write-Log "Service '$serviceName' restarted but status is $($svc.Status) after renewal of $domain" -Level WARNING
                        }
                    }
                    catch { Write-Log "Failed to restart service '$serviceName' after renewal of ${domain}: $($_.Exception.Message)" -Level ERROR }
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

    # Outcome for telemetry (liveness payload, spec section7) + Event Log in main
    $nextExpiry = $null
    foreach ($d in $domains) {
        if ($d.NotAfter) {
            try {
                $dt = [datetime]$d.NotAfter
                if (-not $nextExpiry -or $dt -lt $nextExpiry) { $nextExpiry = $dt }
            }
            catch { }
        }
    }
    $runOutcome =
        if ($DryRun) { 'DryRun' }
        elseif ($renewalFailures.Count -eq 0) { 'Success' }
        elseif ($domains.Count -gt 0 -and $renewalFailures.Count -lt $domains.Count) { 'PartialFailure' }
        else { 'Failure' }
    return [pscustomobject]@{
        RunOutcome = $runOutcome
        CertCount  = $domains.Count
        Renewed    = $renewedCount
        Failures   = @($renewalFailures)
        NextExpiry = if ($nextExpiry) { $nextExpiry.ToString('yyyy-MM-dd HH:mm:ss') } else { $null }
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
    Write-Log "=== Renew-Cert v$ScriptVersion starting (DryRun=$DryRun, CheckOnly=$CheckOnly, SkipSelfUpdate=$SkipSelfUpdate) ===" -Level INFO
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
        $secrets = Get-Secrets   # fail closed if missing

        if (-not $SkipSelfUpdate) {
            if (Invoke-SelfUpdate -Config $config) {
                Write-Log 'Exiting after self-update; the new version runs on the next schedule.' -Level INFO
                try { Stop-Transcript | Out-Null } catch { }
                exit 0
            }
        }
        else { Write-Log 'Self-update skipped (-SkipSelfUpdate).' -Level INFO }

        $outcome = Invoke-RenewalCore -Config $config -Secrets $secrets

        if ($outcome.RunOutcome -eq 'Success') { Write-EventLogEntry $EID.RenewSuccess Information 'Renewal run succeeded' }
        elseif ($outcome.Failures.Count -gt 0)  { Write-EventLogEntry $EID.RenewFailure Error "Renewal run had $($outcome.Failures.Count) failure(s)" }

        Send-Telemetry -Config $config -Outcome $outcome   # liveness signal (stub in PR A)

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
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBU8r/UIoeRb9O/
# 00/FCyK51Yt+2SMG5D89XSmIqh+n9KCCF6gwggRqMIIC0qADAgECAhA9a+7a4tnR
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
# gjcCARUwLwYJKoZIhvcNAQkEMSIEIEsuxUOfM4BwqyuHgyXNh23Ebs10y4oQMRbz
# EcM32pFfMA0GCSqGSIb3DQEBAQUABIIBgD8VOIFZmg+iG9DVisnwjsiMl/QdCbmf
# SMQ2rnU11XQiXOqJTqTGuRo3n6XLFn7LAAlgdH3QANK0KI5SPo5HcCG9lX/AHHaN
# HRCFeHjbt1U/8gz9KV85h/9ETJ6Fk65+lsSL/piDAyyEmw2W3sEjXYUW2jbAUKhP
# UDwwN9HzzM9txV8mKNBpt/quGnkHw9/II2YG8ZuRSs6kfKL5d+fPngldg2r0dLix
# /Rb0e9SRXPHw5jwv2BlXXy1CfJuJ4eMN31L4UvM+nesGz3ci/iv0bHHeBIrFRqbL
# YOYRjLRTJvucdSnJnn3FG9w3Eq5Jn/Fqys0/vGZ4+PRhV/w0PHldIX9Zs08PmWif
# 6EPOgwHcLneAhrWTccBQeJL/8dqwqF6p3toNi/RiZlj28ExZn/UCYXNPbglT61Um
# KGkYvF94rFG+lHyRvatYJUfRA0eUUQaNZGVJJ8jKy5pU55dg+DBchNXQrngRgy9I
# Wsg7QdgpiVOCzR/HO3sM/Peq28qR23nWe6GCAyYwggMiBgkqhkiG9w0BCQYxggMT
# MIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5j
# LjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNB
# NDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZIAWUD
# BAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEP
# Fw0yNjA2MTYwNzI5NTVaMC8GCSqGSIb3DQEJBDEiBCBUOvWxRsH3Bwgb51FSgyZC
# 2mNzgyBp4sV12Ki6U1drpDANBgkqhkiG9w0BAQEFAASCAgCuwY32WWsAVdzpXUEn
# 3bkClMKunhRwQbu7lg9YMG8kRMFW5ZEY8PXh9hFzujvcMdnMgjph8YkzmSUT19M3
# blAFnC/CVc8fGMlrC3+7GY3oiiAYIHT352EJJy6rdYPmoiTjRqZqnQEl6sK9KqaG
# a72GKnV264sUnCB0/N6H/e5Ub56AgiWDw0quspQBXkzf/trA0zbecOubS8Nf6uwZ
# pYl4IhNx4zaxK4ozPAjoPX8vybLatAQ0oCJ2yckydbK8pXhLZpq8QVmiYkoZbglD
# IbPGhsi9OWkJpC294b1A4EC6zsJ+U5fqN1W6dX69xAEgmWsO/U7h7+Waw+FMNtEn
# 7EPWdEwKuB/6K9c0vKFTPk6gP3bWZe/6w3cGdw2X+m9eefKjV4jOQ9YDxmGImnnv
# c/mmI3szDi35FQgw6wql6uhGKls1YcyOmYs2HakRLCeDYObijPia2zUKKgz10B8Q
# mOYH9VKWI1eXLv1hwFOVR9dVJ7gJ1jtKMcEOy1m2EpWz9si6yeReQuRq/jQy7gRh
# rO+vM/DCKB4vIyIymu7FlSghijy0GJ9zLWwoiAC2mZz8/Boti9FbYcqu+YEAcMJf
# 2NW1aCMwvVMULJGXcXRNo9AjYAN4OG1BnhagDBzAi5hTeRshOHRWAqf5G6ZVBSev
# 48FXAdGJIX9OokSGYoEf7mFHnA==
# SIG # End signature block
