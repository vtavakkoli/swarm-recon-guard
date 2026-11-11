<#
Freeze clean Git checkout, build matching Docker image, auto-generate evidence.
Usage: .\scripts\run_publication.ps1 -Suite cove-confirmation
#>
param(
    [ValidateSet('reviewer-controls', 'cove-confirmation')]
    [string]$Suite = 'cove-confirmation'
)
$ErrorActionPreference = 'Stop'
if (git status --porcelain) {
    throw 'Refusing publication experiment from a dirty or untracked Git checkout.'
}
if ($LASTEXITCODE -ne 0) { throw 'Git status failed.' }
$env:SWARM_COMMIT = (git rev-parse --verify HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $env:SWARM_COMMIT -notmatch '^[a-f0-9]{40}$') {
    throw 'Unable to identify an exact Git commit.'
}
Write-Host "Building and running frozen revision $env:SWARM_COMMIT"
docker compose build --no-cache
if ($LASTEXITCODE -ne 0) { throw 'Docker build failed.' }
docker compose run --rm experiment run --suite "/app/scenarios/$Suite.yaml"
if ($LASTEXITCODE -ne 0) { throw 'Docker publication experiment/evidence generation failed.' }
$archive = Get-ChildItem .\results -File -Filter "$Suite-*-evidence.zip" |
    Sort-Object Name -Descending | Select-Object -First 1
if (-not $archive -or $archive.Length -le 0) {
    throw 'No complete evidence ZIP was produced.'
}
Write-Host "Reviewer evidence: $($archive.FullName)"
Write-Host "Source commit: $env:SWARM_COMMIT"
