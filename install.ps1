# Open Cloud Agents: Windows Universal Installer (PowerShell)
# https://open-cloud-agents.github.io/ocagents/
#
# Usage:
#   irm https://open-cloud-agents.github.io/ocagents/install.ps1 | iex

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "☁️  Installing Open Cloud Agents CLI (ocagents)..." -ForegroundColor Cyan
Write-Host ("=" * 66)

$installDir = Join-Path $HOME ".open-cloud-agents"
$binDir = Join-Path $installDir "bin"
$repoUrl = "https://github.com/open-cloud-agents/ocagents.git"
$repoName = "open-cloud-agents/ocagents"
$releaseTag = if ($env:OCAGENTS_VERSION) { $env:OCAGENTS_VERSION } else { "latest" }

if (-not (Test-Path $binDir)) {
    New-Item -ItemType Directory -Path $binDir -Force | Out-Null
}

# 1. Attempt Standalone Hermetic Binary Download (64-bit Windows)
$is64Bit = [System.Environment]::Is64BitOperatingSystem
$installedStandalone = $false

if ($is64Bit) {
    $binaryName = "ocagents-windows-amd64.exe"
    if ($releaseTag -eq "latest") {
        $downloadUrl = "https://github.com/$repoName/releases/latest/download/$binaryName"
    } else {
        $downloadUrl = "https://github.com/$repoName/releases/download/$releaseTag/$binaryName"
    }

    $targetExe = Join-Path $binDir "ocagents.exe"
    $aliasExe = Join-Path $binDir "oca.exe"

    try {
        Write-Host "ℹ Detected 64-bit Windows. Checking for standalone hermetic binary..." -ForegroundColor Blue
        Invoke-WebRequest -Uri $downloadUrl -OutFile $targetExe -UseBasicParsing -ErrorAction Stop
        Copy-Item -Path $targetExe -Destination $aliasExe -Force
        Write-Host "  ✔ Installed standalone binary: $targetExe and alias $aliasExe" -ForegroundColor Green
        $installedStandalone = $true
    } catch {
        Write-Host "  ⚠ Standalone binary not yet published for release '$releaseTag'. Falling back to local catalog installation..." -ForegroundColor Yellow
    }
}

# 2. Source Catalog Fallback (Requires Python 3 & Git)
if (-not $installedStandalone) {
    # 2a. Detect Python
    $pythonCmd = $null
    if (Get-Command python -ErrorAction SilentlyContinue) {
        $pythonCmd = "python"
    } elseif (Get-Command py -ErrorAction SilentlyContinue) {
        $pythonCmd = "py"
    } else {
        Write-Host "❌ Error: Python 3 was not found on your system." -ForegroundColor Red
        Write-Host "   Please install Python from https://www.python.org/ or via 'winget install Python.Python.3.12'"
        exit 1
    }

    $pyVersion = & $pythonCmd -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
    Write-Host "  ✔ Found Python $pyVersion ($pythonCmd)" -ForegroundColor Green

    # 2b. Detect Git
    if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
        Write-Host "❌ Error: Git was not found on your system." -ForegroundColor Red
        Write-Host "   Please install Git via 'winget install Git.Git'"
        exit 1
    }
    Write-Host "  ✔ Found Git: $((git --version).Split([Environment]::NewLine)[0])" -ForegroundColor Green

    # 2c. Setup directories & clone
    Write-Host "ℹ Synchronizing canonical agent catalog into: $installDir..." -ForegroundColor Blue

    # Some catalog paths are longer than Windows' default 260-character limit,
    # so every git command that writes files runs with core.longpaths enabled.
    function Assert-GitSucceeded([string]$step) {
        if ($LASTEXITCODE -ne 0) {
            Write-Host "❌ Error: git $step failed (exit code $LASTEXITCODE)." -ForegroundColor Red
            Write-Host "   If the error says 'Filename too long', run: git config --global core.longpaths true"
            exit 1
        }
    }

    if (Test-Path (Join-Path $installDir ".git")) {
        git -c core.longpaths=true -C "$installDir" fetch origin main --quiet
        Assert-GitSucceeded "fetch"
        git -c core.longpaths=true -C "$installDir" reset --hard origin/main --quiet
        Assert-GitSucceeded "reset"
        Write-Host "  ✔ Updated existing installation to latest main branch." -ForegroundColor Green
    } elseif (Test-Path $installDir) {
        Remove-Item -Recurse -Force $installDir
        git -c core.longpaths=true clone --depth=1 "$repoUrl" "$installDir" --quiet
        Assert-GitSucceeded "clone"
        Write-Host "  ✔ Replaced catalog with fresh clone." -ForegroundColor Green
    } else {
        git -c core.longpaths=true clone --depth=1 "$repoUrl" "$installDir" --quiet
        Assert-GitSucceeded "clone"
        Write-Host "  ✔ Cloned canonical catalog successfully." -ForegroundColor Green
    }

    # 2d. Create Launchers in bin/
    $cmdLauncher = Join-Path $binDir "ocagents.cmd"
    $cmdOca = Join-Path $binDir "oca.cmd"
    $psLauncher = Join-Path $binDir "ocagents.ps1"

    @"
@echo off
set "OCAGENTS_HOME=%USERPROFILE%\.open-cloud-agents"
python "%OCAGENTS_HOME%\src\ocagents\cli.py" %*
"@ | Set-Content -Path $cmdLauncher -Encoding ASCII

    @"
@echo off
"%~dp0ocagents.cmd" %*
"@ | Set-Content -Path $cmdOca -Encoding ASCII

    @"
`$env:OCAGENTS_HOME = "`$HOME\.open-cloud-agents"
python "`$env:OCAGENTS_HOME\src\ocagents\cli.py" @args
"@ | Set-Content -Path $psLauncher -Encoding UTF8

    Write-Host "  ✔ Created command launchers: ocagents, oca" -ForegroundColor Green
}

# 3. Configure User PATH
$userPath = [Environment]::GetEnvironmentVariable("Path", [EnvironmentVariableTarget]::User)
if ($userPath -split ";" -notcontains $binDir) {
    $newUserPath = "$userPath;$binDir"
    [Environment]::SetEnvironmentVariable("Path", $newUserPath, [EnvironmentVariableTarget]::User)
    $env:Path = "$env:Path;$binDir"
    Write-Host "  ✔ Added $binDir to User PATH environment variable." -ForegroundColor Green
} else {
    $env:Path = "$env:Path;$binDir"
}

# 4. Verify Installation
Write-Host ("-" * 66)
Write-Host "ℹ Verifying CLI installation..." -ForegroundColor Blue
if ($installedStandalone) {
    & (Join-Path $binDir "ocagents.exe") info
} else {
    & $pythonCmd "$installDir\src\ocagents\cli.py" info
}

Write-Host ""
Write-Host "🎉 Open Cloud Agents (ocagents) installed successfully!" -ForegroundColor Green
Write-Host ("=" * 66)
Write-Host "Quickstart Commands:" -ForegroundColor White
Write-Host "  • List all agents:          ocagents -agents list (or ocagents -a ls)" -ForegroundColor Cyan
Write-Host "  • Sync for GitHub Copilot:  ocagents sync -A --format github --target ." -ForegroundColor Cyan
Write-Host "  • Sync for Claude Code:     ocagents sync -A --format claude --target ." -ForegroundColor Cyan
Write-Host "  • Sync for Cursor:          ocagents sync -A --format cursor --target ." -ForegroundColor Cyan
Write-Host "  • Validate specs & tests:   ocagents validate" -ForegroundColor Cyan
Write-Host "  • Update agent catalog:     ocagents update" -ForegroundColor Cyan
Write-Host ""
