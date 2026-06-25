#Requires -Version 5.1
<#
.SYNOPSIS
  One-time setup for the Entra Application Proxy certificate sync (issue #64). Run elevated by a Graph
  admin on each fleet server that publishes a cert through Application Proxy.
.DESCRIPTION
  The fourth published, signed artifact of cert-renewal v2 (sibling of Create-New-Cert.ps1). It registers
  (or reuses) the shared "AppProxy-Certificate-Updater" Entra app, mints a non-exportable auth certificate
  in LocalMachine\My, uploads its public key, grants the Graph app-roles + admin consent, and writes the
  shared AppProxyAuth block into cert-config.json. After this runs, the daily SYSTEM renewal
  (Renew-Cert.ps1) pushes each renewed cert into its Application Proxy app inline - no second scheduled
  task, no poller (the renewal already has the new thumbprint in hand). Per-domain wiring (which cert ->
  which App Proxy app) is done in Create-New-Cert.ps1's Add/Update flows.

  This is the ONLY script that touches the Microsoft Graph PowerShell SDK, and only the two sub-modules it
  needs (Microsoft.Graph.Authentication + Microsoft.Graph.Applications), installed on demand. The renewal
  and creator talk to Graph over raw cert-auth REST (no SDK) to keep the SYSTEM renewal path lean.

  Modes:
   - (default) fresh setup: register/reuse the app + auth cert, write AppProxyAuth.
   - -Migrate: adopt an existing standalone AdHoc App Proxy install (reuse its app + auth cert, map its
     AppProxies[] onto our Domains[] by certificate subject/SAN, unregister its 3:30 AM task, archive its
     scripts/config). Idempotent, best-effort, mirrors bootstrap's v1->v2 migration.
.PARAMETER DryRun
  Read-only: log what WOULD happen; no module install, no Entra writes, no cert mint, no config write,
  no task unregister.
.PARAMETER Migrate
  Adopt an existing AdHoc App Proxy install instead of a fresh registration (see -OldAppProxyConfigPath).
.PARAMETER ConfigPath
  cert-config.json to update (default C:\Cert\Renewal\cert-config.json).
.PARAMETER OldAppProxyConfigPath
  The AdHoc tool's config to migrate from (default C:\Cert\AppProxy\AppProxyConfig.json). -Migrate only.
.NOTES
  Source of truth : iteam-as/private-certrenewal (this repo, src/). Published (signed) to
  iteam-as/public-certrenewal by .github/workflows/release.yml on a v*.*.* tag. Do NOT edit the
  public copy by hand. Self-contained: helpers (Write-Log, Write-EventLogEntry, Test-IsElevated,
  Get-CertConfig) mirror Renew-Cert.ps1's; the config writer is intentionally telemetry-free (the renewal
  owns the telemetry path). Event IDs: Setup-AppProxy owns 1300-1350.
#>
[CmdletBinding()]
param(
    [switch] $DryRun,
    [switch] $Migrate,
    [string] $ConfigPath            = 'C:\Cert\Renewal\cert-config.json',
    [string] $OldAppProxyConfigPath = 'C:\Cert\AppProxy\AppProxyConfig.json'
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# CI replaces 'DEV' with the release tag (e.g. 2.7.0) at publish time.
$ScriptVersion = '2.7.0'

# The shared Entra app (one per tenant) the fleet authenticates as to update App Proxy certs.
$AppName = 'AppProxy-Certificate-Updater'

# Graph SDK sub-modules - only the two we use (NOT the full Microsoft.Graph meta-module, NOT Users /
# Identity.DirectoryManagement which the AdHoc #Requires lists but our flow never calls).
$GraphModules = @('Microsoft.Graph.Authentication', 'Microsoft.Graph.Applications')

# Graph app-role ids (well-known): Application.ReadWrite.All + Directory.ReadWrite.All on the Graph SP.
$GraphResourceId       = '00000003-0000-0000-c000-000000000000'
$AppReadWriteAllRole   = '1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9'
$DirectoryReadWriteAll = '19dbc75e-c2e2-444c-a770-ec69d8559fc7'

# The AdHoc install we migrate from (-Migrate).
$OldAppProxyTaskName = 'AppProxy-CertificateUpdate'

# Windows Event Log (source shared with renewal/creator/bootstrap; Setup-AppProxy owns 1300-1350).
$EventLogName   = 'Application'
$EventLogSource = 'CertRenewal'
$EID = @{ Start = 1300; AppRegistered = 1310; AuthCertMinted = 1320; ConfigWritten = 1330; Migrated = 1340; Failed = 1350 }

#region Helpers ---------------------------------------------------------------

function Write-Log {
    # Mirrors Renew-Cert.ps1's Write-Log (kept identical so the four scripts read the same).
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
    # Mirrors Renew-Cert.ps1's Write-EventLogEntry. Best-effort; never fatal.
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
    catch { Write-Log "Event Log write skipped (id $EventId): $($_.Exception.Message)" -Level DEBUG }
}

function Test-IsElevated {
    # True if the current process runs with the Administrators role (required for LocalMachine cert
    # stores, machine-wide modules, and unregistering the AdHoc scheduled task).
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($id)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

# --- Console UI -------------------------------------------------------------
# The same presentation layer as Create-New-Cert.ps1 so the two interactive tools read alike: headers +
# rules for section boundaries, aligned 'label ...... value' info rows, and Ok/Note/Warn inline feedback.
# Helpers are COPIED VERBATIM from the creator (Get-UiGlyph / Write-UiRule / Write-UiHeader / Write-UiField /
# Write-UiSetting / Write-UiOption / Write-UiResult / Read-UiInput) - keep them byte-identical if the creator's
# change. Rules/glyphs use Unicode on a UTF-8 console, ASCII elsewhere ($script:UiUnicode set in Main).

function Get-UiGlyph {
    param([Parameter(Mandatory)][ValidateSet('Rule', 'Ok', 'Arrow', 'Dot')][string] $Name)
    $uni = ($script:UiUnicode -eq $true)
    switch ($Name) {
        'Rule'  { if ($uni) { [string][char]0x2500 } else { '-' } }
        'Ok'    { if ($uni) { [string][char]0x2713 } else { '[ok]' } }
        'Arrow' { if ($uni) { [string][char]0x2192 } else { '->' } }
        'Dot'   { if ($uni) { [string][char]0x00B7 } else { '-' } }
    }
}

function Write-UiRule {
    param([int] $Width = 64)
    Write-Host (' ' + ((Get-UiGlyph Rule) * $Width)) -ForegroundColor DarkCyan
}

function Write-UiHeader {
    param([Parameter(Mandatory)][string] $Title)
    Write-Host ''
    Write-Host " $Title" -ForegroundColor Cyan
    Write-UiRule
}

function Write-UiField {
    # Aligned 'label ...... value' information row; the value column is fixed so values line up regardless of
    # label length. Empty value renders as (none).
    param([Parameter(Mandatory)][string] $Label, [string] $Value, [int] $LabelWidth = 20)
    if ([string]::IsNullOrEmpty($Value)) { $Value = '(none)' }
    $leader = "{0} {1}" -f $Label, ('.' * [Math]::Max(3, ($LabelWidth - $Label.Length)))
    Write-Host ("   {0} " -f $leader.PadRight($LabelWidth + 2)) -ForegroundColor DarkGray -NoNewline
    Write-Host $Value -ForegroundColor White
}

function Write-UiSetting {
    # Sub-heading naming the thing being decided; -Current (when bound) shows the existing value.
    param([Parameter(Mandatory)][string] $Name, [string] $Current)
    Write-Host ''
    if ($PSBoundParameters.ContainsKey('Current')) {
        $shown = if ([string]::IsNullOrWhiteSpace($Current)) { 'none' } else { $Current }
        Write-Host " $Name" -ForegroundColor White -NoNewline
        Write-Host "   (current: $shown)" -ForegroundColor DarkGray
    }
    else { Write-Host " $Name" -ForegroundColor White }
}

function Write-UiOption {
    # The available choices for the current question (keys called out).
    param([Parameter(Mandatory)][string] $Text)
    Write-Host "   $Text" -ForegroundColor DarkYellow
}

function Write-UiResult {
    # Inline feedback after an answer: Ok (check), Note (arrow, dim), Warn (arrow, yellow).
    param([Parameter(Mandatory)][string] $Text, [ValidateSet('Ok', 'Note', 'Warn')][string] $Kind = 'Note')
    switch ($Kind) {
        'Ok'   { Write-Host ("   {0} {1}" -f (Get-UiGlyph Ok), $Text) -ForegroundColor Green }
        'Warn' { Write-Host ("   {0} {1}" -f (Get-UiGlyph Arrow), $Text) -ForegroundColor Yellow }
        default { Write-Host ("   {0} {1}" -f (Get-UiGlyph Arrow), $Text) -ForegroundColor DarkGray }
    }
}

function Read-UiInput {
    # The single question primitive: ' > ' marks "type something now". -Default (when non-empty) is shown in
    # brackets. Returns the raw string (callers trim/parse). Goes through Read-Host so prompts stay mockable.
    param([Parameter(Mandatory)][string] $Prompt, [string] $Default)
    $label = if ($PSBoundParameters.ContainsKey('Default') -and $Default -ne '') { "$Prompt [$Default]" } else { $Prompt }
    return (Read-Host " >  $label")
}

function Get-CertConfig {
    if (-not (Test-Path $ConfigPath)) { throw "cert-config.json not found at $ConfigPath (run bootstrap / Create-New-Cert.ps1 first)" }
    try { return Get-Content $ConfigPath -Raw | ConvertFrom-Json }
    catch { throw "cert-config.json is not valid JSON: $($_.Exception.Message)" }
}

function Backup-Config {
    # Snapshot the current cert-config.json before overwrite, into <config dir>\config-backups\ as
    # cert-config.<timestamp>.<reason>.json (newest 20 kept) - the SAME convention the creator/renewal use
    # (Backup-CertConfig), so all backups live in one place. Best-effort; no-op when the file is absent.
    param([string] $Reason = 'AppProxy setup')
    try {
        if (-not (Test-Path -LiteralPath $ConfigPath)) { return }
        $backupDir = Join-Path (Split-Path -Parent $ConfigPath) 'config-backups'
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

function Save-Config {
    # Persist the (mutated) cert-config object. DryRun-gated; snapshots the previous file to config-backups\
    # first (best-effort, via Backup-Config). Telemetry-free by design - the renewal owns the telemetry
    # path; this is interactive admin tooling.
    param([Parameter(Mandatory)][object] $Config, [string] $Reason = 'AppProxy setup')
    if ($DryRun) { Write-Log "[DryRun] WOULD save cert-config.json ($Reason)." -Level INFO; return }
    try {
        Backup-Config -Reason $Reason
        $Config | ConvertTo-Json -Depth 10 | Out-File -FilePath $ConfigPath -Force -Encoding UTF8
        Write-Log "cert-config.json saved ($Reason)." -Level SUCCESS
        Write-EventLogEntry $EID.ConfigWritten Information "cert-config.json updated by Setup-AppProxy ($Reason)"
    }
    catch { throw "Failed to save cert-config.json: $($_.Exception.Message)" }
}

function Install-GraphModules {
    # Ensure the two Graph sub-modules we use are present (machine-wide so any admin context can load them).
    # On demand, mirroring bootstrap's Install-RequiredModules. DryRun-gated.
    if ($DryRun) { Write-Log "[DryRun] WOULD ensure NuGet + PSGallery trust + install (AllUsers): $($GraphModules -join ', ')." -Level INFO; return }
    try {
        if (-not (Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue)) {
            Write-Log 'Installing NuGet package provider...' -Level INFO
            Install-PackageProvider -Name NuGet -MinimumVersion '2.8.5.201' -Force -Scope AllUsers | Out-Null
        }
        if ((Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue).InstallationPolicy -ne 'Trusted') {
            Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue
        }
    }
    catch { Write-Log "Package provider / repository prep had a problem: $($_.Exception.Message). Continuing." -Level WARNING }

    foreach ($m in $GraphModules) {
        if (Get-Module -ListAvailable -Name $m) { Write-Log "  Module '$m' already installed." -Level DEBUG; continue }
        Write-Log "Installing module '$m' (AllUsers)..." -Level INFO
        Install-Module -Name $m -Scope AllUsers -Force -AllowClobber -ErrorAction Stop | Out-Null
        Write-Log "  Installed '$m'." -Level SUCCESS
    }
    foreach ($m in $GraphModules) { Import-Module $m -ErrorAction Stop }
}

function Connect-Graph {
    # Interactive Graph sign-in for the admin running setup. Returns the tenant id. The scopes are the ones
    # needed to register the app, upload the cert, and grant the app-role assignments.
    if ($DryRun) { Write-Log '[DryRun] WOULD Connect-MgGraph (Application.ReadWrite.All, AppRoleAssignment.ReadWrite.All, Directory.ReadWrite.All).' -Level INFO; return $null }
    # Suppress the SDK's welcome / connection banner on EVERY stream it might use: -NoWelcome is honored
    # inconsistently across Graph SDK versions, and the banner has been observed on the Information stream
    # (6) AND the success stream. Redirect both (6>$null + Out-Null) and silence Information at the source
    # (-InformationAction); -ErrorAction Stop still throws because the error stream is NOT redirected.
    # Without this the banner leaked into this function's output and got saved as AppProxyAuth.TenantId,
    # producing an "Invalid URL" 400 when the renewal built the token endpoint from it.
    Connect-MgGraph -Scopes 'Application.ReadWrite.All', 'AppRoleAssignment.ReadWrite.All', 'Directory.ReadWrite.All' `
        -NoWelcome -ErrorAction Stop -InformationAction SilentlyContinue 6>$null | Out-Null
    $ctx = Get-MgContext
    if (-not $ctx) { throw 'Connect-MgGraph did not establish a context.' }
    # Guard: the tenant id is written into cert-config.json and used to build the AAD token URL, so it MUST
    # be a GUID. If Get-MgContext ever returns something else, fail loudly rather than persist a bad value.
    $tid = [string]$ctx.TenantId
    if ($tid -notmatch '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') {
        throw "Get-MgContext returned an unexpected tenant id ('$tid') - aborting rather than writing a bad AppProxyAuth.TenantId."
    }
    Write-UiResult "connected as $($ctx.Account) (tenant $tid)" -Kind Ok
    return $tid
}

function Get-OrCreateAuthCertificate {
    # Mint (or reuse) the non-exportable self-signed auth cert in LocalMachine\My (CN=<AppName>-Auth).
    # Reuses an existing cert with >30 days left. Lifted from the AdHoc manager. DryRun returns $null.
    if ($DryRun) { Write-Log "[DryRun] WOULD mint/reuse the auth certificate CN=$AppName-Auth in LocalMachine\My (non-exportable, 2y)." -Level INFO; return $null }
    $subject = "CN=$AppName-Auth"
    $existing = Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue | Where-Object {
        $_.Subject -eq $subject -and $_.HasPrivateKey -and $_.NotAfter -gt (Get-Date).AddDays(30)
    } | Sort-Object NotAfter -Descending | Select-Object -First 1
    if ($existing) {
        Write-UiResult "reusing existing auth cert $($existing.Thumbprint) (expires $($existing.NotAfter.ToString('yyyy-MM-dd')))" -Kind Ok
        return $existing
    }
    Write-UiResult "minting a new non-exportable auth cert ($subject, 2 years)..." -Kind Note
    $cert = New-SelfSignedCertificate -Subject $subject -CertStoreLocation 'Cert:\LocalMachine\My' `
        -KeyExportPolicy NonExportable -KeySpec Signature -KeyLength 2048 -KeyAlgorithm RSA -HashAlgorithm SHA256 `
        -NotAfter (Get-Date).AddYears(2) -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.2') `
        -Provider 'Microsoft Enhanced RSA and AES Cryptographic Provider'
    Write-UiResult "minted auth cert $($cert.Thumbprint) (expires $($cert.NotAfter.ToString('yyyy-MM-dd')))" -Kind Ok
    Write-EventLogEntry $EID.AuthCertMinted Information "App Proxy auth cert minted ($($cert.Thumbprint))"
    return $cert
}

function Get-OrCreateEntraApp {
    # Register (or reuse) the shared AppProxy-Certificate-Updater app, upload the auth cert's PUBLIC key,
    # add the Graph app-roles, and grant admin consent. Returns @{ AppId; ObjectId }. Lifted from the AdHoc
    # Get-OrCreateEntraApp (Graph SDK). DryRun returns a placeholder.
    param([System.Security.Cryptography.X509Certificates.X509Certificate2] $AuthCertificate)
    if ($DryRun) {
        Write-Log "[DryRun] WOULD register/reuse Entra app '$AppName', upload the auth cert, and grant Application.ReadWrite.All + Directory.ReadWrite.All." -Level INFO
        return @{ AppId = '(dry-run)'; ObjectId = '(dry-run)' }
    }

    $app = Get-MgApplication -Filter "displayName eq '$AppName'" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($app) {
        Write-UiResult "reusing existing Entra app '$AppName' (appId $($app.AppId))" -Kind Ok
    }
    else {
        Write-UiResult "registering new Entra app '$AppName'..." -Kind Note
        $app = New-MgApplication -DisplayName $AppName -SignInAudience 'AzureADMyOrg'
        Write-UiResult "registered app (appId $($app.AppId))" -Kind Ok
    }

    $sp = Get-MgServicePrincipal -Filter "appId eq '$($app.AppId)'" -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $sp) { $sp = New-MgServicePrincipal -AppId $app.AppId; Write-UiResult 'created service principal' -Kind Note }

    # Upload the auth cert public key (append if not already present).
    $hash = [System.Convert]::ToBase64String($AuthCertificate.GetCertHash())
    $already = $app.KeyCredentials | Where-Object { $_.CustomKeyIdentifier -and [System.Convert]::ToBase64String($_.CustomKeyIdentifier) -eq $hash }
    if ($already) {
        Write-UiResult 'auth certificate already registered on the app' -Kind Note
    }
    else {
        $keyCred = @{
            Type        = 'AsymmetricX509Cert'
            Usage       = 'Verify'
            Key         = $AuthCertificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
            DisplayName = "Auth-Cert-$($AuthCertificate.Thumbprint.Substring(0,8))"
        }
        Update-MgApplication -ApplicationId $app.Id -KeyCredentials @(@($app.KeyCredentials) + $keyCred)
        Write-UiResult "uploaded auth certificate $($AuthCertificate.Thumbprint) to the app" -Kind Ok
    }

    # Ensure the required Graph permissions are declared.
    Update-MgApplication -ApplicationId $app.Id -RequiredResourceAccess @(@{
        ResourceAppId  = $GraphResourceId
        ResourceAccess = @(
            @{ Id = $AppReadWriteAllRole;   Type = 'Role' },
            @{ Id = $DirectoryReadWriteAll; Type = 'Role' }
        )
    })

    # Grant admin consent (idempotent: skip a role already assigned).
    $graphSp = Get-MgServicePrincipal -Filter "appId eq '$GraphResourceId'" | Select-Object -First 1
    $existingAssignments = @(Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -ErrorAction SilentlyContinue)
    foreach ($roleId in @($AppReadWriteAllRole, $DirectoryReadWriteAll)) {
        if ($existingAssignments | Where-Object { $_.AppRoleId -eq $roleId -and $_.ResourceId -eq $graphSp.Id }) {
            Write-UiResult "Graph app-role $roleId already granted" -Kind Note
            continue
        }
        New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -PrincipalId $sp.Id -ResourceId $graphSp.Id -AppRoleId $roleId | Out-Null
        Write-UiResult "granted Graph app-role $roleId" -Kind Ok
    }

    Write-EventLogEntry $EID.AppRegistered Information "Entra app '$AppName' configured (appId $($app.AppId))"
    return @{ AppId = [string]$app.AppId; ObjectId = [string]$app.Id }
}

function Set-AppProxyAuthBlock {
    # Write/refresh the shared AppProxyAuth block on the cert-config object (thumbprint is a public
    # reference - no secret stored, golden rule). Idempotent.
    param(
        [Parameter(Mandatory)][object] $Config,
        [Parameter(Mandatory)][string] $TenantId,
        [Parameter(Mandatory)][string] $ClientId,
        [Parameter(Mandatory)][string] $AuthCertThumbprint
    )
    # Defence-in-depth: TenantId + ClientId are written here and used to build the AAD token URL at renewal
    # time. Refuse to persist anything that isn't a GUID (e.g. a Graph SDK welcome banner that leaked into
    # the value) - a bad TenantId yields an "Invalid URL" 400 that only surfaces days later on the box.
    # Skipped under -DryRun, where the values are the '(dry-run)' placeholder (nothing is persisted anyway).
    if (-not $DryRun) {
        foreach ($pair in @(@{ N = 'TenantId'; V = $TenantId }, @{ N = 'ClientId'; V = $ClientId })) {
            if ($pair.V -notmatch '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') {
                throw "Refusing to write AppProxyAuth: $($pair.N) is not a GUID ('$($pair.V)')."
            }
        }
    }
    $block = [pscustomobject][ordered]@{
        Enabled            = $true
        TenantId           = $TenantId
        ClientId           = $ClientId
        AuthCertThumbprint = $AuthCertThumbprint
        ApplicationName    = $AppName
    }
    $Config | Add-Member -NotePropertyName 'AppProxyAuth' -NotePropertyValue $block -Force
    return $Config
}

function Get-CertificateIdentities {
    # The set of FQDNs a Domains[] entry covers (MainDomain + SANs), lowercased, for migration matching.
    param([object] $DomainEntry)
    $ids = @()
    if ($DomainEntry.MainDomain) { $ids += ([string]$DomainEntry.MainDomain).ToLower() }
    if ($DomainEntry.SANs) { foreach ($s in @($DomainEntry.SANs)) { if ($s) { $ids += ([string]$s).ToLower() } } }
    return @($ids | Select-Object -Unique)
}

function Get-OldProxyIdentities {
    # The FQDNs an old AdHoc AppProxies[] entry covers (CN of CertificateSubject + CertificateSANs).
    param([object] $OldProxy)
    $ids = @()
    if ($OldProxy.CertificateSubject -and ([string]$OldProxy.CertificateSubject -match 'CN=([^,]+)')) { $ids += $Matches[1].Trim().ToLower() }
    if ($OldProxy.CertificateSANs) { foreach ($s in @($OldProxy.CertificateSANs)) { if ($s) { $ids += ([string]$s).ToLower() } } }
    return @($ids | Select-Object -Unique)
}

function Add-MigratedAppProxyBindings {
    # Map each AdHoc AppProxies[] entry onto a Domains[] entry by certificate subject/SAN and stamp a
    # per-domain AppProxy block (Add-Member). Returns @{ Mapped = <int>; Unmapped = @(<label>...) }. Pure of
    # I/O (the caller persists), so the migration mapping is unit-testable.
    param([Parameter(Mandatory)][object] $Config, [Parameter(Mandatory)][object] $OldConfig)
    $domains = @(); if ($Config.Domains) { $domains = @($Config.Domains) }
    $mapped = 0; $unmapped = @()
    foreach ($op in @($OldConfig.AppProxies)) {
        $opIds = Get-OldProxyIdentities -OldProxy $op
        $match = $null
        foreach ($d in $domains) {
            $dIds = Get-CertificateIdentities -DomainEntry $d
            if ($dIds | Where-Object { $opIds -contains $_ }) { $match = $d; break }
        }
        if (-not $match) { $unmapped += "$($op.DisplayName) [$($opIds -join ', ')]"; continue }
        $match | Add-Member -NotePropertyName 'AppProxy' -NotePropertyValue ([pscustomobject]@{
            ApplicationObjectId = [string]$op.ApplicationObjectId
            AppId               = [string]$op.AppId
            DisplayName         = [string]$op.DisplayName
        }) -Force
        Write-UiResult "mapped App Proxy '$($op.DisplayName)' $(Get-UiGlyph Arrow) certificate '$($match.MainDomain)'" -Kind Ok
        $mapped++
    }
    return @{ Mapped = $mapped; Unmapped = @($unmapped) }
}

#endregion Helpers ------------------------------------------------------------

#region Main ------------------------------------------------------------------

$exitCode = 0
# Console-UI glyphs: Unicode rules/marks on a UTF-8 console, ASCII elsewhere (mirrors the creator's Main).
try { $script:UiUnicode = ([Console]::OutputEncoding.CodePage -eq 65001) } catch { $script:UiUnicode = $false }
try {
    Write-EventLogEntry $EID.Start Information "Setup-AppProxy v$ScriptVersion starting (Migrate=$Migrate)"
    $dot     = Get-UiGlyph Dot
    $modeStr = if ($Migrate) { 'migrate an existing AdHoc install' } else { 'fresh setup' }
    Write-UiHeader ("cert-renewal {0} Setup-AppProxy v{1}" -f $dot, $ScriptVersion)
    Write-UiField 'Mode'    $modeStr
    Write-UiField 'Config'  $ConfigPath
    Write-UiField 'Dry run' $(if ($DryRun) { 'yes (no changes will be made)' } else { 'no' })
    Write-UiRule

    if (-not (Test-IsElevated)) { throw 'Setup-AppProxy must run elevated (Administrator) - it writes LocalMachine certs and may unregister a scheduled task.' }

    $config = Get-CertConfig

    Write-UiHeader 'Microsoft Graph'
    Install-GraphModules
    # Connect-Graph does the sign-in + a GUID sanity check, but we deliberately DON'T trust its return
    # value: some Graph SDK versions emit the welcome/connection banner to the success stream even with
    # -NoWelcome + redirection, which contaminates any function return. Discard the return and read the
    # tenant id straight off the SDK context object (always a clean GUID) instead.
    $null = Connect-Graph
    $tenantId = if ($DryRun) { $null } else { [string](Get-MgContext).TenantId }

    Write-UiHeader 'Authentication certificate'
    $authCert = Get-OrCreateAuthCertificate

    Write-UiHeader 'Entra application'
    $entraApp = Get-OrCreateEntraApp -AuthCertificate $authCert

    $authThumb = if ($authCert) { $authCert.Thumbprint } else { '(dry-run)' }
    $clientId  = $entraApp.AppId
    $tenant    = if ($tenantId) { $tenantId } else { '(dry-run)' }
    $mapped = 0; $unmapped = @()

    if ($Migrate) {
        Write-UiHeader 'Migrate existing AdHoc App Proxy install'
        if (-not (Test-Path $OldAppProxyConfigPath)) { throw "No AdHoc config found at $OldAppProxyConfigPath - nothing to migrate (run without -Migrate for a fresh setup)." }
        $old = Get-Content $OldAppProxyConfigPath -Raw | ConvertFrom-Json

        # Reuse the AdHoc app + auth cert when present (no re-register) by preferring the old config's IDs.
        if ($old.ClientId)                 { $clientId = [string]$old.ClientId }
        if ($old.TenantId)                 { $tenant   = [string]$old.TenantId }
        if ($old.AuthCertificateThumbprint -and ($authThumb -eq '(dry-run)')) { $authThumb = [string]$old.AuthCertificateThumbprint }

        $config = Set-AppProxyAuthBlock -Config $config -TenantId $tenant -ClientId $clientId -AuthCertThumbprint $authThumb

        # Map each old AppProxies[] entry onto a Domains[] entry by certificate subject/SAN.
        $map = Add-MigratedAppProxyBindings -Config $config -OldConfig $old
        $mapped = $map.Mapped; $unmapped = @($map.Unmapped)
        if ($unmapped.Count -gt 0) {
            Write-UiResult "could not map $($unmapped.Count) App Proxy entry(ies) - no managed cert matches their subject/SAN:" -Kind Warn
            foreach ($u in $unmapped) { Write-UiResult $u -Kind Warn }
            Write-UiResult 'add the matching cert via Create-New-Cert.ps1, then re-run -Migrate (or wire it via the creator''s Update flow).' -Kind Note
        }

        Save-Config -Config $config -Reason 'AppProxy migration'

        # Unregister the AdHoc scheduled task + archive its scripts/config (the renewal handles it inline now).
        $task = Get-ScheduledTask -TaskName $OldAppProxyTaskName -ErrorAction SilentlyContinue
        if ($task) {
            if ($DryRun) { Write-Log "[DryRun] WOULD unregister the AdHoc scheduled task '$OldAppProxyTaskName'." -Level INFO }
            else { Unregister-ScheduledTask -TaskName $OldAppProxyTaskName -Confirm:$false; Write-UiResult "unregistered the AdHoc scheduled task '$OldAppProxyTaskName'" -Kind Ok }
        }
        else { Write-UiResult "no AdHoc scheduled task '$OldAppProxyTaskName' (already removed?)" -Kind Note }

        $oldDir = Split-Path -Parent $OldAppProxyConfigPath
        if ($oldDir -and (Test-Path $oldDir)) {
            $archive = "$oldDir.migrated-{0}" -f (Get-Date -Format 'yyyyMMdd-HHmmss')
            if ($DryRun) { Write-Log "[DryRun] WOULD archive the old AdHoc folder $oldDir -> $archive." -Level INFO }
            else {
                try { Rename-Item -Path $oldDir -NewName (Split-Path -Leaf $archive) -ErrorAction Stop; Write-UiResult "archived the old AdHoc folder $(Get-UiGlyph Arrow) $archive" -Kind Ok }
                catch { Write-UiResult "could not archive $oldDir (in use?): $($_.Exception.Message). Remove it manually once you've confirmed the migration." -Kind Warn }
            }
        }

        Write-EventLogEntry $EID.Migrated Information "AdHoc App Proxy install migrated ($mapped mapped, $($unmapped.Count) unmapped)"
    }
    else {
        # Fresh setup: just write the shared AppProxyAuth block. Per-domain wiring is done in the creator.
        $config = Set-AppProxyAuthBlock -Config $config -TenantId $tenant -ClientId $clientId -AuthCertThumbprint $authThumb
        Save-Config -Config $config -Reason 'AppProxy fresh setup'
    }

    if (-not $DryRun) {
        try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { }
    }

    Write-UiHeader 'Summary'
    Write-UiField 'Tenant'      $tenant
    Write-UiField 'Application' ("{0} ({1})" -f $AppName, $clientId)
    Write-UiField 'Auth cert'   $authThumb
    if ($Migrate) { Write-UiField 'Mapped' ("{0} App Proxy app(s){1}" -f $mapped, $(if ($unmapped.Count) { ", $($unmapped.Count) unmapped" } else { '' })) }
    Write-UiRule
    if ($Migrate) {
        Write-UiResult 'migration complete - the daily renewal now keeps App Proxy in sync.' -Kind Ok
    }
    else {
        Write-UiResult 'fresh setup complete.' -Kind Ok
        Write-UiResult 'next: wire each certificate to an App Proxy app via Create-New-Cert.ps1 (Add or Update).' -Kind Note
    }
}
catch {
    Write-Log "FATAL: $($_.Exception.Message)" -Level ERROR
    Write-EventLogEntry $EID.Failed Error "Setup-AppProxy failed: $($_.Exception.Message)"
    $exitCode = 1
}

exit $exitCode

#endregion Main ---------------------------------------------------------------

# SIG # Begin signature block
# MIIeDwYJKoZIhvcNAQcCoIIeADCCHfwCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCktG2PZq022CSW
# veUgfZ1PzIB4UTl3fizjxQKoz6wWoaCCF6gwggRqMIIC0qADAgECAhA9a+7a4tnR
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
# gjcCARUwLwYJKoZIhvcNAQkEMSIEIONrQn5FzwaG782z/nJBD+ycgTBffAqUqUsL
# 2TG0hagPMA0GCSqGSIb3DQEBAQUABIIBgJ3JztAVmHNCFSCdNvXXn77CtN2ZH+PM
# Uc9Zm8lEgy4JAuY9Vn6HnR1SpbUz3WDsNxGOxHR8HVJooia/xKqPLLC3+JaKbF+R
# tBtmVSgiN30F9UgwyWggGtmXBTM7+gYl/Q8ZhmsK4g2Jp2ws4JAQkF9rnVIxR1xW
# 8UA7ZHp4l1IJE28T5yUCa3eeo+cRe0jP+EtHh1LrL9enaE1unjYNMwKL+GN0+Lcq
# 5re8Wkfz+aJGgdXhJFET0lqVWq4aWUwxvzLZGC+7HlSAnM23vI7IbMRu29001Ftg
# Y9vSBtHg5JCWOJqvGItWT62SVG2EBI51Vp9bWHGppjgQd6u+LsmStvdXSGLq0I8K
# Z5ZhVybQSztdzgwI2jiisRQrAygiP3cPCZsnziQflztd0SlNFXTfY7wdT+ebCBHn
# 0bS44nJip/IeMBhHYFs0pgp8ZwWHOhd/ZQevhBC/tPk1w6zYUPYXBvUbLBRttnzs
# tWhbNxpvI3FXWe7yLGfuCIfE3a2HIXECRqGCAyYwggMiBgkqhkiG9w0BCQYxggMT
# MIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5j
# LjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNB
# NDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZIAWUD
# BAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEP
# Fw0yNjA2MjUxMjIzMjdaMC8GCSqGSIb3DQEJBDEiBCC4QlJhpOPMRpAIM7sx+FUj
# Lz747BB5+pBP57d4TX3wtzANBgkqhkiG9w0BAQEFAASCAgAwWNWz74oP4h2GLiim
# qgKVaAasur48NaY3X0EYlHQkT8GyLFjVglxTGRYy0VejxzmAz48xE3C/sKITZnEf
# 5WWjNQHnr/Fscaoy3WSgE35CiajE28U5XRjyqUQYkXEsTvrWffsZSmfWVGwFRS0o
# rbiG/+kkc+30R/1Dmtdrh4Twr/72xiwOlAfAs4Gp0vIY/S8YMEQfgjh8yZEohEcK
# P/JIMg8VxCBu5Zch12wO7xTDUBetDcoJ58K1WMs7qaNNo33pBajUDGvZZCCmvZC7
# o2XKYk7RSvCA7qLtMQFsqeajAWSXSW2X6X8J5tUjnkjhUPyXPm71xJlLQdK3gxBi
# hBuc9sjdRzwVU84wN0odolaUaruB+3UieaVlHQRfX8oSJz9wt8ubpj3bymAe4gGC
# WVUef3pIdpO5sIO++fb+exTrt9qTxxkHV4pC7qyyHBClyD6u9rD0SSbDB6IRyGrX
# 3gcNlrVvNfjDzcASE2+0KQSIs1B0qBKtNw1GEeFS6C2AEkjYBuQyOD4ptwTXiAd0
# CP5IAEEOom4ynogBoLK7LiclJP0Yj0BkMECLs8AkPHt+PXXdNXU8TfXCZlbv1kEP
# hNzuEMyD63YXNShd0x1EOopgyHvdV4ltvhL1iEmaglSysWEwT+k3Wha+cgJssMVo
# 9Z6OUS62N4v+OCviqpct3Nh8FQ==
# SIG # End signature block
