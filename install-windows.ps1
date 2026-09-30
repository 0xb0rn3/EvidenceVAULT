# Install EvidenceVault for the current Windows user.
[CmdletBinding()]
param(
    [string]$InstallDir = (Join-Path $env:LOCALAPPDATA 'EvidenceVault'),
    [string]$SourceDirectory = '',
    [ValidatePattern('^[\w.-]+/[\w.-]+$')]
    [string]$SourceRepo = 'DezTheJackal/EvidenceVAULT',
    [ValidatePattern('^(main|[0-9a-fA-F]{40})$')]
    [string]$Revision = 'main',
    [switch]$SkipPythonInstall,
    [switch]$NoPathUpdate
)

& {
$ErrorActionPreference = 'Stop'

function Find-Python {
    $candidates = @()
    $launcher = Get-Command py.exe -ErrorAction SilentlyContinue
    if ($launcher) {
        $candidates += @{ Path = $launcher.Source; Arguments = @('-3.13') }
        $candidates += @{ Path = $launcher.Source; Arguments = @('-3') }
    }
    $command = Get-Command python.exe -ErrorAction SilentlyContinue
    if ($command -and $command.Source -notmatch '\\WindowsApps\\') {
        $candidates += @{ Path = $command.Source; Arguments = @() }
    }
    $candidates += @{
        Path = (Join-Path $env:LOCALAPPDATA 'Programs\Python\Python313\python.exe')
        Arguments = @()
    }
    foreach ($candidate in $candidates) {
        if (-not (Test-Path -LiteralPath $candidate.Path -PathType Leaf)) { continue }
        try {
            $options = $candidate.Arguments
            $probe = & $candidate.Path @options -I -c 'import sys; print(sys.executable); sys.exit(0 if sys.version_info >= (3, 11) else 1)' 2>$null
            if ($LASTEXITCODE -eq 0 -and $probe) { return ([string]$probe).Trim() }
        } catch {
            # Try the next Python command.
        }
    }
    return $null
}

function Install-PythonRuntime([string]$TemporaryDirectory) {
    $winget = Get-Command winget.exe -ErrorAction SilentlyContinue
    if ($winget) {
        Write-Host 'Install Python 3.13 for the current user.'
        & $winget.Source install --id Python.Python.3.13 --exact --source winget --scope user --silent --disable-interactivity --accept-package-agreements --accept-source-agreements
        if ($LASTEXITCODE -eq 0) { return }
        Write-Host 'WinGet could not complete the install. Use the Python installer.'
    }
    # These hashes come from the Microsoft WinGet Python 3.13.15 manifest.
    $architecture = $env:PROCESSOR_ARCHITEW6432
    if (-not $architecture) { $architecture = $env:PROCESSOR_ARCHITECTURE }
    switch ($architecture.ToUpperInvariant()) {
        'AMD64' { $suffix = '-amd64'; $expected = 'EDEC09C4853AEAE9AC36EFB8C9F95B6B8E2FEE65EEE56D9767A8B7C69C574403' }
        'ARM64' { $suffix = '-arm64'; $expected = 'C252C676087C49E6B94E95A273536B78921C28A5FC9F86D15D25392328247249' }
        'X86' { $suffix = ''; $expected = '741C07276EB2D57E7EE012D643F021C58CB38D11C5389BE46C15D41D1A10B447' }
        default { throw 'This Windows processor type is not supported.' }
    }
    $installer = Join-Path $TemporaryDirectory 'python-installer.exe'
    $url = "https://www.python.org/ftp/python/3.13.15/python-3.13.15$suffix.exe"
    Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $installer
    if ((Get-FileHash -LiteralPath $installer -Algorithm SHA256).Hash -ne $expected) {
        throw 'The Python installer hash did not match.'
    }
    $process = Start-Process -FilePath $installer -ArgumentList '/quiet InstallAllUsers=0 PrependPath=0 Include_launcher=1 InstallLauncherAllUsers=0 Include_test=0' -Wait -PassThru
    if ($process.ExitCode -notin @(0, 3010)) { throw 'The Python installer failed.' }
}

function Invoke-EvidenceVaultInstall {
    if ($env:OS -ne 'Windows_NT') { throw 'Run this installer on Windows.' }
    $target = [IO.Path]::GetFullPath($InstallDir)
    if (Test-Path -LiteralPath $target) {
        throw 'The install folder already exists. Use the installed command or select a new folder.'
    }
    $temporary = Join-Path ([IO.Path]::GetTempPath()) ('evidencevault-' + [guid]::NewGuid().ToString('N'))
    $createdTarget = $false
    $oldProtocol = [Net.ServicePointManager]::SecurityProtocol
    try {
        [Net.ServicePointManager]::SecurityProtocol = $oldProtocol -bor [Net.SecurityProtocolType]::Tls12
        New-Item -ItemType Directory -Path $temporary | Out-Null
        $python = Find-Python
        if (-not $python) {
            if ($SkipPythonInstall) { throw 'Python 3.11 or a newer version was not found.' }
            Install-PythonRuntime $temporary
            $python = Find-Python
            if (-not $python) { throw 'Python was installed but could not be started. Open a new terminal and run the installer again.' }
        }
        if ($SourceDirectory) {
            $source = [IO.Path]::GetFullPath($SourceDirectory)
        } else {
            Write-Host 'Download the complete EvidenceVault repository.'
            $archive = Join-Path $temporary 'source.zip'
            Invoke-WebRequest -UseBasicParsing -Uri "https://github.com/$SourceRepo/archive/$Revision.zip" -OutFile $archive
            $expanded = Join-Path $temporary 'source'
            Expand-Archive -LiteralPath $archive -DestinationPath $expanded
            $folders = @(Get-ChildItem -LiteralPath $expanded -Directory)
            if ($folders.Count -ne 1) { throw 'The downloaded repository has an unexpected layout.' }
            $source = $folders[0].FullName
        }
        foreach ($name in @('Evidencevault.py', 'evidencevault\__init__.py', 'LICENSE')) {
            if (-not (Test-Path -LiteralPath (Join-Path $source $name) -PathType Leaf)) {
                throw 'The source folder does not contain the full EvidenceVault project.'
            }
        }
        New-Item -ItemType Directory -Path $target | Out-Null
        $createdTarget = $true
        $app = Join-Path $target 'app'
        $bin = Join-Path $target 'bin'
        New-Item -ItemType Directory -Path $app, $bin | Out-Null
        foreach ($item in Get-ChildItem -LiteralPath $source -Force) {
            if ($item.Name -notin @('.git', '.venv', '__pycache__')) {
                Copy-Item -LiteralPath $item.FullName -Destination $app -Recurse
            }
        }
        Write-Host 'Create the separate Python environment.'
        & $python -I -m venv (Join-Path $target '.venv')
        if ($LASTEXITCODE -ne 0) { throw 'The Python environment could not be created.' }
        $runtime = Join-Path $target '.venv\Scripts\python.exe'
        & $runtime -E -s (Join-Path $app 'Evidencevault.py') --version
        if ($LASTEXITCODE -ne 0) { throw 'The installed program failed its start check.' }
        $wrapper = @'
@echo off
"%~dp0..\.venv\Scripts\python.exe" -E -s "%~dp0..\app\Evidencevault.py" %*
exit /b %errorlevel%
'@
        Set-Content -LiteralPath (Join-Path $bin 'evidencevault.cmd') -Value $wrapper -Encoding ASCII
        if (-not $NoPathUpdate) {
            $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
            $entries = @($userPath -split ';' | Where-Object { $_ })
            if ($entries -notcontains $bin) {
                [Environment]::SetEnvironmentVariable('Path', (($entries + $bin) -join ';'), 'User')
            }
            if (($env:Path -split ';') -notcontains $bin) { $env:Path += ';' + $bin }
        }
        Write-Host ('Installed in ' + $target)
        Write-Host 'Run evidencevault to open the guided menu.'
    } catch {
        if ($createdTarget) { Remove-Item -LiteralPath $target -Recurse -Force }
        throw
    } finally {
        [Net.ServicePointManager]::SecurityProtocol = $oldProtocol
        if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Recurse -Force }
    }
}

Invoke-EvidenceVaultInstall
}
