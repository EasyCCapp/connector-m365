# Microsoft 365 MCP connector build (Windows / cross-platform-ish)
#
# Used by the fork's CI (security-and-build.yml) and local dry runs.
# Produces dist/m365-mcp-win-x64.zip with the upstream's compiled dist/
# + production node_modules + the Carpe launcher, ready to be unzipped
# at the user's machine.
#
# Run from the fork root:
#   .\carpe-fork\build.ps1

[CmdletBinding()]
param(
    [string]$OutputDir = "dist-release",
    [switch]$SkipInstall
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$forkRoot = Split-Path -Parent $PSScriptRoot
Set-Location $forkRoot

Write-Host "[build] Fork root: $forkRoot"
Write-Host "[build] Output dir: $OutputDir"

# 1. Clean install from package-lock.json
if (-not $SkipInstall) {
    Write-Host "[build] Removing any existing node_modules + dist"
    if (Test-Path node_modules) { Remove-Item -Recurse -Force node_modules }
    if (Test-Path dist) { Remove-Item -Recurse -Force dist }

    Write-Host "[build] npm ci"
    & npm ci
    if ($LASTEXITCODE -ne 0) { throw "npm ci failed (exit $LASTEXITCODE)" }

    # Generate the OpenAPI-derived client + compile TypeScript
    Write-Host "[build] npm run generate"
    & npm run generate
    if ($LASTEXITCODE -ne 0) { throw "npm run generate failed (exit $LASTEXITCODE)" }

    Write-Host "[build] npm run build"
    & npm run build
    if ($LASTEXITCODE -ne 0) { throw "npm run build failed (exit $LASTEXITCODE)" }

    # Reinstall with --omit=dev for the shipped bundle. We keep the
    # already-built dist/, but drop dev-only deps from node_modules.
    Write-Host "[build] npm prune --production (drop dev deps from node_modules)"
    & npm prune --production
    if ($LASTEXITCODE -ne 0) { throw "npm prune failed (exit $LASTEXITCODE)" }
}

# 2. Stage the bundle
$staging = Join-Path $env:TEMP "m365-mcp-bundle-$(Get-Random)"
Write-Host "[build] Staging at $staging"
New-Item -ItemType Directory -Path $staging | Out-Null

# Files we ship
$shipPaths = @(
    "dist",
    "node_modules",
    "package.json",
    "package-lock.json",
    "carpe-fork\run.cmd"
)

foreach ($p in $shipPaths) {
    if (-not (Test-Path $p)) {
        throw "Expected path missing from fork tree: $p"
    }
    Write-Host "[build] Copying $p"
    # Copy-Item on a file path drops the file at the destination root.
    # carpe-fork\run.cmd lands at $staging\run.cmd which is what
    # connector.json's `${connector_dir}/run.cmd` launch line expects.
    Copy-Item -Recurse -Path $p -Destination $staging
}

# 3. Zip
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir | Out-Null
}
$zipPath = Join-Path $OutputDir "m365-mcp-win-x64.zip"
if (Test-Path $zipPath) { Remove-Item $zipPath }

Write-Host "[build] Compressing to $zipPath"
Compress-Archive -Path (Join-Path $staging "*") -DestinationPath $zipPath -CompressionLevel Optimal

# 4. SHA-256
$hash = Get-FileHash -Algorithm SHA256 $zipPath
$hashLine = "$($hash.Hash.ToLower())  $(Split-Path -Leaf $zipPath)"
$hashLine | Set-Content -Path "$zipPath.sha256" -NoNewline

Write-Host "[build] Wrote $zipPath"
Write-Host "[build] SHA-256: $($hash.Hash.ToLower())"

# 5. Cleanup
Remove-Item -Recurse -Force $staging
