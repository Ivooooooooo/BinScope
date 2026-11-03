param(
    [string]$Version = "0.1.0"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    $tauri = Join-Path $root "frontend\node_modules\.bin\tauri.cmd"
    if (-not (Test-Path $tauri)) {
        throw "tauri CLI not found at $tauri; run npm install in frontend first"
    }

    Write-Host "Building BinScope (release, no installer)..."
    & $tauri build --no-bundle
    if ($LASTEXITCODE -ne 0) {
        throw "tauri build failed with exit code $LASTEXITCODE"
    }

    $out = Join-Path $root "dist"
    $dest = Join-Path $out "BinScope-Portable"
    if (Test-Path $dest) {
        Remove-Item $dest -Recurse -Force
    }
    New-Item -ItemType Directory -Force $dest | Out-Null
    New-Item -ItemType Directory -Force (Join-Path $dest "rules") | Out-Null
    New-Item -ItemType Directory -Force (Join-Path $dest "databases") | Out-Null

    Copy-Item (Join-Path $root "target\release\binscope-app.exe") (Join-Path $dest "BinScope.exe")
    Copy-Item (Join-Path $root "rules\yara") (Join-Path $dest "rules\yara") -Recurse
    Copy-Item (Join-Path $root "databases\die") (Join-Path $dest "databases\die") -Recurse
    Copy-Item (Join-Path $root "databases\signatures") (Join-Path $dest "databases\signatures") -Recurse
    Copy-Item (Join-Path $root "scripts\portable-README.txt") (Join-Path $dest "README.txt")

    

    

    New-Item -ItemType File -Force (Join-Path $dest "binscope.portable") | Out-Null

    $zip = Join-Path $out "BinScope-Portable-$Version.zip"
    if (Test-Path $zip) {
        Remove-Item $zip -Force
    }
    Compress-Archive -Path (Join-Path $dest "*") -DestinationPath $zip -CompressionLevel Optimal

    $size = (Get-Item $zip).Length
    Write-Host ""
    Write-Host "Portable folder: $dest"
    Write-Host "Portable ZIP:    $zip ($size bytes)"
    Write-Host "SHA-256:         $((Get-FileHash $zip -Algorithm SHA256).Hash)"
}
finally {
    Pop-Location
}
