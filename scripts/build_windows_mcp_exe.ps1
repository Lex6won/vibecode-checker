[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$PythonExecutable,
  [string]$OutputDirectory = (Join-Path $PSScriptRoot "..\dist\windows-mcp"),
  [string]$PyInstallerVersion = "6.22.3",
  [switch]$AllowDirty
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repo = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
$python = (Resolve-Path -LiteralPath $PythonExecutable).Path
$output = [System.IO.Path]::GetFullPath($OutputDirectory)
$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("gvskb-mcp-build-" + [Guid]::NewGuid().ToString("N"))

if ((Get-Item -LiteralPath $python).Name -ne "python.exe") {
  throw "PythonExecutable must point to a real Python 3.11+ python.exe."
}
if (Test-Path -LiteralPath $output) {
  $existing = @(Get-ChildItem -LiteralPath $output -Force)
  if ($existing.Count -gt 0) { throw "OutputDirectory must be empty: $output" }
} else {
  New-Item -ItemType Directory -Path $output -Force | Out-Null
}

try {
  $wheelDirectory = Join-Path $tempRoot "wheel"
  $venvDirectory = Join-Path $tempRoot "venv"
  New-Item -ItemType Directory -Path $wheelDirectory -Force | Out-Null

  $wheelArgs = @((Join-Path $repo "scripts\build_wheel.py"), "--out", $wheelDirectory)
  if ($AllowDirty) { $wheelArgs += "--allow-dirty" }
  & $python @wheelArgs
  if ($LASTEXITCODE -ne 0) { throw "The identity-bearing checker wheel build failed." }

  $wheel = Get-ChildItem -LiteralPath $wheelDirectory -Filter "vibecode_checker-*.whl" | Sort-Object LastWriteTime | Select-Object -Last 1
  if ($null -eq $wheel) { throw "The checker wheel was not created." }

  & $python -m venv $venvDirectory
  if ($LASTEXITCODE -ne 0) { throw "The isolated executable build environment could not be created." }
  $buildPython = Join-Path $venvDirectory "Scripts\python.exe"
  & $buildPython -m pip install --disable-pip-version-check --quiet "pyinstaller==$PyInstallerVersion" $wheel.FullName
  if ($LASTEXITCODE -ne 0) { throw "Pinned PyInstaller or the checker wheel could not be installed." }

  & $buildPython -m PyInstaller `
    --clean `
    --noconfirm `
    --onefile `
    --name gvskb-server `
    --distpath $output `
    --workpath (Join-Path $tempRoot "work") `
    --specpath (Join-Path $tempRoot "spec") `
    --collect-all gvskb `
    --collect-all fastmcp `
    --copy-metadata vibecode-checker `
    (Join-Path $repo "scripts\gvskb_server_entry.py")
  if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed to build gvskb-server.exe." }

  $executable = Join-Path $output "gvskb-server.exe"
  if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) { throw "gvskb-server.exe was not created." }
  $hash = (Get-FileHash -LiteralPath $executable -Algorithm SHA256).Hash.ToLowerInvariant()
  $record = [ordered]@{
    status = "local_test_candidate_built"
    executable = $executable
    sha256 = $hash
    pyinstaller_version = $PyInstallerVersion
    production_approved = $false
    note = "기관 서명·승인 전 로컬 시험 후보입니다. 운영 배포에 사용하지 마세요."
  }
  $record | ConvertTo-Json -Depth 4
} finally {
  $resolvedTemp = [System.IO.Path]::GetFullPath($tempRoot)
  $systemTemp = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
  if ($resolvedTemp.StartsWith($systemTemp, [System.StringComparison]::OrdinalIgnoreCase) -and (Test-Path -LiteralPath $resolvedTemp)) {
    Remove-Item -LiteralPath $resolvedTemp -Recurse -Force
  }
}
