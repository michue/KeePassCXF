# SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
# SPDX-FileCopyrightText: Copyright (C) 2026 Michael Hüpkes
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Modifications from original
# - 2026-11-26: adjusted paths for this project
# - 2026-11-26: removed functions that are not necessary for this project
# - 2026-11-26: removed hard coded plugin name from functions and replaced with a parameter
Set-StrictMode -Version Latest

function Write-Step([string]$msg) {
	Write-Host "`n==> $msg" -ForegroundColor Cyan
}

function Assert-Elevation {
	$id = [Security.Principal.WindowsIdentity]::GetCurrent()
	$p  = [Security.Principal.WindowsPrincipal]$id
	if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
		Write-Warning "This script must run as Administrator."
		Write-Warning "Re-launch PowerShell as Admin and run the script again."
		# Keep the window open so the message is readable when launched from a profile that closes
		# its console on exit. Skip the wait when there is no interactive console (e.g. CI).
		if ([Environment]::UserInteractive) {
			Read-Host "Press Enter to close" | Out-Null
		}
		exit 1
	}
}

# Returns hashtable: FileVersion, Version (e.g. "1.0.0-dev")
# Mirrors the MSBuild rule in Directory.Build.props: Debug builds get 'dev' unless VersionSuffix is explicitly set.
function Get-BuildVersions([string]$RepoRoot, [string]$Configuration = '') {
	$props = [xml](Get-Content "$RepoRoot\src\Directory.Build.props")
	$fileVersionNode = $props.SelectSingleNode('//FileVersion')
	if (-not $fileVersionNode) { throw "FileVersion not found in src/Directory.Build.props" }
	$fileVersion = $fileVersionNode.InnerText
	$prefixNode  = $props.SelectSingleNode('//VersionPrefix')
	$suffixNode  = $props.SelectSingleNode('//VersionSuffix')
	$prefix = if ($prefixNode) { $prefixNode.InnerText } else { '' }
	$suffix = if ($suffixNode) { $suffixNode.InnerText } else { '' }
	# Debug is always 'dev'
	if ($Configuration -eq 'Debug') { $suffix = 'dev' }
	$version = if ($suffix) { "$prefix-$suffix" } else { $prefix }
	return @{ FileVersion = $fileVersion; Version = $version }
}

# Builds the KeePass plugin DLL. -Optimized turns on IL optimization for a Debug-identity build.
function Invoke-BuildPlugin {
	param(
		[string]$RepoRoot,
		[string]$PluginName,
		[string]$Configuration,
		[switch]$Optimized
	)
	$csproj = "$RepoRoot\src\$($PluginName)Plugin\$($PluginName)Plugin.csproj"
	$sw = [System.Diagnostics.Stopwatch]::StartNew()
	if ($Optimized) {
		& dotnet build $csproj -c $Configuration /p:SolutionDir="$RepoRoot\" --nologo /p:Optimized=true
	} else {
		& dotnet build $csproj -c $Configuration /p:SolutionDir="$RepoRoot\" --nologo
	}
	if ($LASTEXITCODE -ne 0) { throw "dotnet build failed with exit code $LASTEXITCODE" }
	Write-Host "  Build OK.  ($([math]::Round($sw.Elapsed.TotalSeconds, 1))s)"
}

function Invoke-GenerateLicenseNotices {
	param(
		[string]$RepoRoot,
		[string]$OutputFile
	)
	$toolList = & dotnet tool list --global 2>&1
	if (-not ($toolList | Select-String 'nuget-license')) {
		Write-Host "  Installing nuget-license..."
		& dotnet tool install --global nuget-license --verbosity quiet
		if ($LASTEXITCODE -ne 0) { throw "Failed to install nuget-license" }
	}

	# Test packages never ship, so they stay out of the notices
	$projects = Get-ChildItem -Path "$RepoRoot\src" -Filter '*.csproj' -Recurse |
					   Where-Object { $_.Name -notlike '*.Tests.csproj' } |
					   Select-Object -ExpandProperty FullName

	Write-Host "  Restoring NuGet packages..."
	foreach ($proj in $projects) {
		& dotnet restore $proj --verbosity quiet
		if ($LASTEXITCODE -ne 0) { throw "dotnet restore failed for $proj (exit $LASTEXITCODE)" }
	}

	$result   = [System.Collections.Generic.List[string]]::new()
	$seenPkgs = @{}

	foreach ($proj in $projects) {
		$projName  = [IO.Path]::GetFileNameWithoutExtension($proj)
		$lines     = & nuget-license -i $proj --include-transitive
		if ($LASTEXITCODE -ne 0) { throw "nuget-license failed (exit $LASTEXITCODE) for $(Split-Path $proj -Leaf)" }
		$dataLines = @($lines | Where-Object { $_ })

		$result.Add('')
		$result.Add("# $projName")
		if ($dataLines.Count -eq 0) {
			$result.Add('  (no third-party packages)')
		} else {
			foreach ($line in $dataLines) { $result.Add([string]$line) }
		}

		$jsonLines = & nuget-license -i $proj --include-transitive -o Json
		if ($LASTEXITCODE -ne 0) { throw "nuget-license JSON pass failed for $(Split-Path $proj -Leaf)" }
		($jsonLines | ConvertFrom-Json) | ForEach-Object {
			$key = "$($_.PackageId)_$($_.PackageVersion)"
			if (-not $seenPkgs.ContainsKey($key)) { $seenPkgs[$key] = $_ }
		}
	}

	# SPDX-identified packages grouped by expression, text fetched from the SPDX data repository
	$byLicense = $seenPkgs.Values |
				 Where-Object { $_.License } |
				 Group-Object License |
				 Sort-Object Name

	$result.Add('')
	$result.Add('---')
	$result.Add('# License Texts')

	foreach ($group in $byLicense) {
		$expression = $group.Name
		$pkgs       = $group.Group | Sort-Object PackageId

		$result.Add('')
		$result.Add("## $expression")
		$result.Add('')
		$result.Add('Packages:')
		foreach ($pkg in $pkgs) { $result.Add("  $($pkg.PackageId) $($pkg.PackageVersion)") }
		$result.Add('')

		$spdxUrl = "https://raw.githubusercontent.com/spdx/license-list-data/main/text/$expression.txt"
		try {
			$licText = (Invoke-WebRequest -Uri $spdxUrl -UseBasicParsing -ErrorAction Stop).Content
			foreach ($line in ($licText -split '\r?\n')) { $result.Add($line) }
		} catch {
			$result.Add("[License text unavailable. See: $spdxUrl]")
		}
	}

	# Bundled source that is NOT delivered as a NuGet package, so nuget-license can't see it
	# (e.g. headers hand-transcribed into P/Invoke bindings). Each *.notice.txt under src/
	# is a ready-formatted notice block, co-located with the code it covers; drop one in
	# next to the relevant source to add an entry.
	$srcDir = Join-Path $RepoRoot 'src'
	$noticeFiles = @(Get-ChildItem -Path $srcDir -Filter '*.notice.txt' -Recurse -ErrorAction SilentlyContinue | Sort-Object FullName)
	if ($noticeFiles.Count -gt 0) {
		$result.Add('')
		$result.Add('---')
		$result.Add('# Bundled Source (non-package)')
		foreach ($file in $noticeFiles) {
			$result.Add('')
			foreach ($line in (Get-Content -LiteralPath $file.FullName)) { $result.Add([string]$line) }
		}
	}

	$result | Set-Content -Path $OutputFile -Encoding utf8
	Write-Host "  Generated: $(Split-Path $OutputFile -Leaf)"
}

# Reads ProductVersion (includes git hash) from the plugin DLL via PE resource - no assembly loading.
function Get-PluginVersion([string]$BuildDir, [string]$PluginName) {
	$dllPath = Join-Path $BuildDir "$($PluginName).dll"
	if (-not (Test-Path $dllPath)) { throw "Plugin DLL not found: $dllPath" }
	return [System.Diagnostics.FileVersionInfo]::GetVersionInfo($dllPath).ProductVersion
}

Export-ModuleMember -Function Write-Step, Assert-Elevation, Get-BuildVersions, Invoke-BuildPlugin,
								Invoke-GenerateLicenseNotices, Get-PluginVersion
