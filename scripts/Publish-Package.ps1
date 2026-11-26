# SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
# SPDX-FileCopyrightText: Copyright (C) 2026 Michael Hüpkes
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Modifications from original
# - 2026-11-26: adjusted paths for this project
# - 2026-11-26: removed steps that are not necessary for this project
# - 2026-11-26: made the plugin name a global configuration item
#Requires -Version 5.1
<#
.SYNOPSIS
	Builds, signs, and packages KeePassCXF for distribution.

.DESCRIPTION
	1. Generates THIRD_PARTY_NOTICES.txt
	2. Builds the KeePassCXF.dll KeePass plugin (dotnet build).
	3. Produces a zip archive ready for distribution:
		 KeePassCXF-<version>.zip
		   KeePassCXF.dll
		   KeePassCXF.pdb        (for Debug configurations)
		   README.md
		   THIRD_PARTY_NOTICES.txt
	4. Performs an Antivirus self-check using Microsoft Defender

.PARAMETER Configuration
	Selects identity only: Release = product identity, Debug = dev identity
	Output is release-like optimized by default	(see -NoOptimize). Defaults to Release.

.PARAMETER Dev
	Build the dev-identity package (maps to Configuration Debug):
	optimized like a release, stamped with the 'dev' version suffix.

.PARAMETER SkipBuild
	Skip build and publish steps; use if you already have build output.

.PARAMETER NoOptimize
	Skip release-like optimization (single-file, trimming, IL optimize), producing a plain debuggable
	build. Only meaningful for the Debug configuration; Release stays optimized via the props default.
	The zip is tagged 'unopt'.

.EXAMPLE
	.\Publish-Package.ps1
	.\Publish-Package.ps1 -Dev
	.\Publish-Package.ps1 -SkipBuild
	.\Publish-Package.ps1 -Configuration Debug
	.\Publish-Package.ps1 -Configuration Debug -NoOptimize
#>
param(
	[ValidateSet('Debug', 'Release')]
	[string]$Configuration = 'Release',
	[switch]$SkipBuild,
	[switch]$Dev,
	[switch]$NoOptimize
)

$script:PluginName = 'KeePassCXF'

# -Dev maps to the Debug identity. Output is release-like optimized by default (see -NoOptimize);
# Configuration here only chooses product (Release) vs dev (Debug) identity. Debug auto-stamps 'dev'.
if ($Dev) { $Configuration = 'Debug' }

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module "$PSScriptRoot\Shared.psm1" -Force

$RepoRoot = Split-Path $PSScriptRoot -Parent
$ThirdPartyNoticesName = 'THIRD_PARTY_NOTICES.txt'

$versions = Get-BuildVersions $RepoRoot -Configuration $Configuration
Write-Host "$($script:PluginName) $($versions.Version) ($Configuration)" -ForegroundColor White

# -- 1. Generate notices (must precede MSIX build so the file is included) ----
$noticesPath = "$RepoRoot\build\$ThirdPartyNoticesName"
New-Item (Split-Path $noticesPath) -ItemType Directory -Force | Out-Null
Write-Step "Generating third-party license notices"
Invoke-GenerateLicenseNotices -RepoRoot $RepoRoot -OutputFile $noticesPath

# -- 2. Build -------------------------------------------------------------------
if (-not $SkipBuild) {
	# Release-like optimized by default; -NoOptimize produces a plain debuggable build (Debug only).
	$optimized = -not $NoOptimize

	# Build the plugin (the provider copies it into KeePass's Plugins folder).
	Write-Step "Building $($script:PluginName) plugin DLL"
	Invoke-BuildPlugin -RepoRoot $RepoRoot -PluginName $script:PluginName -Configuration $Configuration -Optimized:$optimized
}

# -- 3. Locate build artifacts --------------------------------------------------
$buildDir = "$RepoRoot\build\$Configuration"

# -- 4. Assemble zip ------------------------------------------------------------
$tags = @()
if ($Configuration -eq 'Debug') { $tags += 'debug' }
if ($NoOptimize)                { $tags += 'unopt' }
$suffix     = if ($tags.Count -gt 0) { '-' + ($tags -join '-') } else { '' }
$zipName    = "$($script:PluginName)-$($versions.Version)$suffix.zip"
$stagingDir = "$RepoRoot\build\publish-staging"
$zipPath    = "$RepoRoot\build\$zipName"

if (Test-Path $stagingDir) { Remove-Item $stagingDir -Recurse -Force }
New-Item $stagingDir -ItemType Directory | Out-Null

Write-Step "Assembling release archive: $zipName"

# Dev-identity (Debug) builds ship plugin PDBs so testers' KeePass logs carry file/line numbers;
# these stay useful after optimization for stack-trace symbolication. Stable Release ships .dll only.
$pluginExtensions = if ($Configuration -eq 'Debug') { '.dll', '.pdb' } else { '.dll' }
Get-ChildItem $buildDir -File | Where-Object { $_.Extension -in $pluginExtensions } | Copy-Item -Destination $stagingDir

Copy-Item "$RepoRoot\README.md" "$stagingDir\README.md"
Copy-Item "$RepoRoot\LICENSE"   "$stagingDir\LICENSE"
# Copy-Item $noticesPath          "$stagingDir\$ThirdPartyNoticesName"

if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
Compress-Archive -Path "$stagingDir\*" -DestinationPath $zipPath
Remove-Item $stagingDir -Recurse -Force

Write-Host "Archive: $zipPath"

# Verify by listing zip entries
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [IO.Compression.ZipFile]::OpenRead($zipPath)
Write-Host "Zip entries:"
$zip.Entries | ForEach-Object { Write-Host "  $($_.FullName)  ($([math]::Round($_.Length / 1KB, 1)) KB)" }
$zip.Dispose()

$hash    = (Get-FileHash $zipPath -Algorithm SHA256).Hash
$zipSize = [math]::Round((Get-Item $zipPath).Length / 1MB, 2)

$productVersion = Get-PluginVersion -BuildDir $buildDir -PluginName $script:PluginName

# -- 5. Antivirus self-check (Microsoft Defender) -------------------------------
# Scan every shipped artifact with the same engine that produces Defender's cloud/ML verdicts, so a
# regression is caught before release. Writes a full per-file report plus a short console overview.
Write-Step "Scanning artifacts with Microsoft Defender"
$scanReport  = "$RepoRoot\build\defender-scan-$($versions.Version)$suffix.txt"
$scanSummary = ''
$scanColor   = 'Green'
$scanFailed  = $false
# Prefer the up-to-date versioned platform copy; fall back to the base install.
$mpCmd = Get-ChildItem "$env:ProgramData\Microsoft\Windows Defender\Platform\*\MpCmdRun.exe" -ErrorAction SilentlyContinue |
Sort-Object LastWriteTime -Descending | Select-Object -First 1 -ExpandProperty FullName
if (-not $mpCmd -and (Test-Path "$env:ProgramFiles\Windows Defender\MpCmdRun.exe")) {
	$mpCmd = "$env:ProgramFiles\Windows Defender\MpCmdRun.exe"
}

if (-not $mpCmd) {
	$scanSummary = 'SKIPPED - MpCmdRun.exe not found, artifacts were NOT scanned'
	$scanColor   = 'Yellow'
	Write-Host "  WARNING: MpCmdRun.exe not found; Microsoft Defender is unavailable." -ForegroundColor Yellow
	Write-Host "  The release artifacts were NOT antivirus-scanned. Verify on a machine with Defender." -ForegroundColor Yellow
	@(
		'Microsoft Defender scan SKIPPED',
		"  Date:    $(Get-Date -Format 'u')",
		"  Version: $($versions.Version)$suffix ($Configuration)",
		'  Reason:  MpCmdRun.exe not found (Microsoft Defender unavailable on this machine).',
		'  Result:  Artifacts were NOT scanned; this build has not been antivirus-verified.'
	) | Set-Content $scanReport -Encoding UTF8
} else {
	# Artifacts: the zip, the MSIX, the provider exe + all its loose DLLs, and the merged plugin DLL.
	$scanTargets = @($zipPath)
	$scanTargets += "$buildDir\$($script:PluginName).dll"
	$scanTargets = $scanTargets | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique

	# -DisableRemediation: report only, never quarantine/delete the build output. 0 = clean, 2 = threat.
	$results = @(foreach ($file in $scanTargets) {
			& $mpCmd -Scan -ScanType 3 -File $file -DisableRemediation | Out-Null
			$code    = $LASTEXITCODE
			$verdict = switch ($code) { 0 { 'CLEAN' } 2 { 'THREAT' } default { "ERROR($code)" } }
			[pscustomobject]@{ Verdict = $verdict; File = $file }
		})
	$threats = @($results | Where-Object { $_.Verdict -eq 'THREAT' })
	$errored = @($results | Where-Object { $_.Verdict -like 'ERROR*' })
	$clean   = @($results | Where-Object { $_.Verdict -eq 'CLEAN' })

	# Full per-file report to its own file. Cloud (MAPS) state is recorded because the !ml/!cl
	# cloud/ML verdicts only reproduce when cloud-delivered protection is on (2 = Advanced).
	$report  = @(
		'Microsoft Defender scan report',
		"  Date:          $(Get-Date -Format 'u')",
		"  Version:       $($versions.Version)$suffix ($Configuration)",
		"  MpCmdRun:      $mpCmd",
		"  Signatures:    $((Get-MpComputerStatus).AntivirusSignatureVersion)",
		"  Cloud (MAPS):  $((Get-MpPreference).MAPSReporting)  (2 = Advanced)",
		"  Result:        $($results.Count) scanned, $($clean.Count) clean, $($threats.Count) threats, $($errored.Count) errors",
		''
	)
	$report += $results | ForEach-Object { '  [{0,-9}] {1}' -f $_.Verdict, $_.File }
	$report | Set-Content $scanReport -Encoding UTF8

	if ($threats.Count -gt 0) {
		$scanSummary = "$($threats.Count) THREAT(S) detected - see report"
		$scanColor   = 'Red'
		$scanFailed  = $true
		Write-Host "  THREATS DETECTED in $($threats.Count) file(s):" -ForegroundColor Red
		$threats | ForEach-Object { Write-Host "    $($_.File)" -ForegroundColor Red }
	} elseif ($errored.Count -gt 0) {
		$scanSummary = "$($clean.Count)/$($results.Count) clean, $($errored.Count) could not be scanned"
		$scanColor   = 'Yellow'
		Write-Host "  $scanSummary" -ForegroundColor Yellow
	} else {
		$scanSummary = "all $($results.Count) artifacts clean"
		Write-Host "  $scanSummary" -ForegroundColor Green
	}
	Write-Host "  Report: $scanReport"
}

Write-Step "Done"
Write-Host "  Version:   $productVersion ($Configuration)" -ForegroundColor Green
Write-Host "  Archive:   $zipPath ($zipSize MB)" -ForegroundColor Green
Write-Host "  SHA256:    $hash" -ForegroundColor Green
Write-Host "  AV scan:   $scanSummary" -ForegroundColor $scanColor

# Fail the build (non-zero exit) so CI blocks a release when Defender flags an artifact.
if ($scanFailed) {
	Write-Host ''
	Write-Host "Microsoft Defender flagged one or more artifacts; see $scanReport" -ForegroundColor Red
	exit 1
}