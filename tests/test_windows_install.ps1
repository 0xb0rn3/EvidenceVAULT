# Check Windows setup with local source or an exact source download.
param([switch]$NetworkSource)
$ErrorActionPreference = 'Stop'
$repository = Split-Path -Parent $PSScriptRoot
$temporary = Join-Path ([IO.Path]::GetTempPath()) ('evidencevault-test-' + [guid]::NewGuid().ToString('N'))
$target = Join-Path $temporary 'install folder'
$installer = Join-Path $repository 'install-windows.ps1'
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
try {
    $options = @{ InstallDir = $target; SkipPythonInstall = $true; NoPathUpdate = $true }
    if ($NetworkSource) {
        $options.Revision = $env:GITHUB_SHA
    } else {
        $options.SourceDirectory = $repository
    }
    & $installer @options
    $command = Join-Path $target 'bin\evidencevault.cmd'
    $version = & $command --version
    if ($LASTEXITCODE -ne 0 -or $version -notmatch 'EvidenceVault 1\.1\.1') {
        throw 'The installed command did not return the expected version.'
    }
    $case = Join-Path $temporary 'sample case'
    & $command collect (Join-Path $repository 'examples\sample-case') -o $case --case WINDOWS-DEMO --operator Student
    if ($LASTEXITCODE -ne 0) { throw 'The installed command could not prepare a case.' }
    foreach ($name in @('case.vault.zip', 'manifest.json', 'audit.sqlite3', 'report.html')) {
        if (-not (Test-Path -LiteralPath (Join-Path $case $name) -PathType Leaf)) {
            throw ('A case output is missing: ' + $name)
        }
    }
    & $command verify (Join-Path $case 'case.vault.zip')
    if ($LASTEXITCODE -ne 0) { throw 'The installed command could not check the case.' }
    $blocked = $false
    try { & $installer -InstallDir $target -SourceDirectory $repository -SkipPythonInstall -NoPathUpdate }
    catch { $blocked = $_.Exception.Message -match 'already exists' }
    if (-not $blocked) { throw 'The installer did not protect an existing folder.' }
    if ([Environment]::GetEnvironmentVariable('Path', 'User') -ne $userPath) {
        throw 'The offline install test changed the user PATH.'
    }
    Write-Host 'The Windows install, launcher, case workflow, and repeat-install checks passed.'
} finally {
    if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Recurse -Force }
}
