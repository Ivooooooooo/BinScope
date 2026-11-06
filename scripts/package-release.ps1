param(
    [switch]$SkipTests,
    [switch]$SkipBuild,
    [string]$Version = "0.1.0"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$releaseRoot = Join-Path $root "release"
$portableDir = Join-Path $releaseRoot "portable"
$githubDir = Join-Path $releaseRoot "github"
$zipPath = Join-Path $releaseRoot "BinScope-Portable-$Version.zip"
$tauri = Join-Path $root "frontend\node_modules\.bin\tauri.cmd"

function Assert-UnderRoot([string]$path) {
    $full = [IO.Path]::GetFullPath($path)
    $rootFull = [IO.Path]::GetFullPath($root).TrimEnd('\') + '\'
    if (-not $full.StartsWith($rootFull, [StringComparison]::OrdinalIgnoreCase)) {
        throw "refusing to modify a path outside the repository: $full"
    }
    return $full
}

function Remove-Staging([string]$path) {
    $full = Assert-UnderRoot $path
    if (Test-Path -LiteralPath $full) {
        Remove-Item -LiteralPath $full -Recurse -Force
    }
}

function Copy-Tree(
    [string]$source,
    [string]$destination,
    [string[]]$excludedSegments = @()
) {
    $sourceFull = [IO.Path]::GetFullPath($source)
    foreach ($file in Get-ChildItem -LiteralPath $sourceFull -Recurse -File -Force) {
        $relative = $file.FullName.Substring($sourceFull.Length).TrimStart('\')
        $skip = $false
        foreach ($segment in $excludedSegments) {
            if (("\" + $relative + "\").ToLowerInvariant().Contains("\" + $segment.ToLowerInvariant() + "\")) {
                $skip = $true
                break
            }
        }
        if ($skip) { continue }
        if ($file.Name -match '\.(log|tmp|pdb)$' -or $file.Name -eq '.DS_Store') { continue }
        $target = Join-Path $destination $relative
        $targetParent = Split-Path -Parent $target
        New-Item -ItemType Directory -Force -Path $targetParent | Out-Null
        Copy-Item -LiteralPath $file.FullName -Destination $target -Force
    }
}

function Copy-File([string]$relative, [string]$destination) {
    $source = Join-Path $root $relative
    if (-not (Test-Path -LiteralPath $source)) {
        throw "required file is missing: $relative"
    }
    Copy-Item -LiteralPath $source -Destination (Join-Path $destination $relative) -Force
}

Write-Host "BinScope release staging"
Write-Host "Repository: $root"
Write-Host ""

if (-not (Test-Path -LiteralPath $tauri)) {
    throw "tauri CLI not found at $tauri; run npm install in frontend first"
}

if (-not $SkipTests) {
    Write-Host "Running Rust format, clippy and workspace tests..."
    & cargo fmt --all -- --check
    if ($LASTEXITCODE -ne 0) { throw "cargo fmt check failed" }
    & cargo clippy --workspace --all-targets -- -D warnings
    if ($LASTEXITCODE -ne 0) { throw "cargo clippy failed" }
    & cargo test --workspace
    if ($LASTEXITCODE -ne 0) { throw "cargo test failed" }

    Write-Host "Running frontend tests and build..."
    & npm --prefix frontend test
    if ($LASTEXITCODE -ne 0) { throw "frontend tests failed" }
    & npm --prefix frontend run build
    if ($LASTEXITCODE -ne 0) { throw "frontend build failed" }
}

if (-not $SkipBuild) {
    Write-Host "Building release executable (no installer)..."
    & $tauri build --no-bundle
    if ($LASTEXITCODE -ne 0) { throw "tauri build failed with exit code $LASTEXITCODE" }
}

$builtExe = Join-Path $root "target\release\binscope-app.exe"
if (-not (Test-Path -LiteralPath $builtExe)) {
    throw "release executable is missing: $builtExe"
}

Write-Host "Staging release/portable..."
Remove-Staging $portableDir
New-Item -ItemType Directory -Force -Path $portableDir | Out-Null
Copy-Item -LiteralPath $builtExe -Destination (Join-Path $portableDir "BinScope.exe") -Force
New-Item -ItemType File -Force -Path (Join-Path $portableDir "binscope.portable") | Out-Null
Copy-Tree (Join-Path $root "rules\yara") (Join-Path $portableDir "rules\yara")
Copy-Tree (Join-Path $root "databases\die") (Join-Path $portableDir "databases\die")
Copy-Tree (Join-Path $root "databases\signatures") (Join-Path $portableDir "databases\signatures")
Copy-Item -LiteralPath (Join-Path $root "scripts\portable-README.txt") -Destination (Join-Path $portableDir "README.txt") -Force



$allowedPortable = @(
    "BinScope.exe",
    "binscope.portable",
    "README.txt",
    "SHA256SUMS.txt"
)
foreach ($item in Get-ChildItem -LiteralPath $portableDir -Force) {
    if ($item.PSIsContainer) {
        if ($item.Name -notin @("rules", "databases")) {
            throw "unexpected directory in portable staging: $($item.Name)"
        }
    } elseif ($item.Name -notin $allowedPortable) {
        throw "unexpected file in portable staging: $($item.Name)"
    }
}

$exeHash = (Get-FileHash -LiteralPath (Join-Path $portableDir "BinScope.exe") -Algorithm SHA256).Hash
@(
    "$exeHash  BinScope.exe"
) | Set-Content -LiteralPath (Join-Path $portableDir "SHA256SUMS.txt") -Encoding ASCII

if (Test-Path -LiteralPath $zipPath) { Remove-Item -LiteralPath $zipPath -Force }
Compress-Archive -Path (Join-Path $portableDir "*") -DestinationPath $zipPath -CompressionLevel Optimal
$zipHash = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash
@(
    "$exeHash  portable/BinScope.exe",
    "$zipHash  BinScope-Portable-$Version.zip"
) | Set-Content -LiteralPath (Join-Path $releaseRoot "SHA256SUMS.txt") -Encoding ASCII

Write-Host "Staging release/github..."
Remove-Staging $githubDir
New-Item -ItemType Directory -Force -Path $githubDir | Out-Null

$rootFiles = @(
    "Cargo.toml", "Cargo.lock", "LICENSE", "README.md", "README.es.md", ".gitignore", ".gitattributes"
)
foreach ($file in $rootFiles) { Copy-File $file $githubDir }

$excludedSegments = @("target", "node_modules", ".git", "dist", "release", ".hallmark", "gen")
foreach ($dir in @("crates", "src-tauri", "frontend", "rules", "databases", "tests", "scripts", ".github")) {
    $source = Join-Path $root $dir
    if (Test-Path -LiteralPath $source) {
        Copy-Tree $source (Join-Path $githubDir $dir) $excludedSegments
    }
}



$generated = Join-Path $githubDir "src-tauri\gen"
if (Test-Path -LiteralPath $generated) { Remove-Item -LiteralPath $generated -Recurse -Force }



$forbiddenDirs = @("target", "node_modules", ".git", "release", "dist", ".hallmark", "gen")
foreach ($item in Get-ChildItem -LiteralPath $githubDir -Recurse -Directory -Force) {
    if ($item.Name -in $forbiddenDirs) {
        throw "forbidden directory staged in release/github: $($item.FullName)"
    }
}
$forbiddenExtensions = @(".pdb", ".log", ".tmp", ".pfx", ".key", ".pem", ".crt", ".csr")
foreach ($item in Get-ChildItem -LiteralPath $githubDir -Recurse -File -Force) {
    if ($item.Extension.ToLowerInvariant() -in $forbiddenExtensions) {
        throw "forbidden file staged in release/github: $($item.FullName)"
    }
}



$secretPatterns = @(
    'ghp_[A-Za-z0-9]{20,}',
    'github_pat_[A-Za-z0-9_]{20,}',
    'sk-[A-Za-z0-9]{20,}',
    'AKIA[0-9A-Z]{16}',
    'BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY',
    ('C:\\Users\\' + 'RE\\'),
    ('C:/Users/' + 'RE/')
)
$textExtensions = @(".rs", ".ts", ".tsx", ".js", ".jsx", ".json", ".toml", ".lock", ".md", ".txt", ".css", ".html", ".yml", ".yaml", ".ps1", ".sh", ".nsh", ".gitignore", ".gitattributes")
$violations = @()
foreach ($file in Get-ChildItem -LiteralPath $githubDir -Recurse -File -Force) {
    if ($file.Extension.ToLowerInvariant() -notin $textExtensions -and $file.Name -notin @(".gitignore", ".gitattributes")) { continue }
    if ($file.Length -gt 2MB) { continue }
    

    if ($file.FullName -eq (Join-Path $githubDir "scripts\package-release.ps1")) { continue }
    $content = [IO.File]::ReadAllText($file.FullName, [Text.Encoding]::UTF8)
    foreach ($pattern in $secretPatterns) {
        if ($content -match $pattern) {
            $violations += "$($file.FullName): matched $pattern"
        }
    }
}
if ($violations.Count -gt 0) {
    throw ("staged GitHub content failed validation:`n" + ($violations -join "`n"))
}



$required = @(
    "Cargo.toml", "Cargo.lock", "README.md", "LICENSE",
    "crates\core\Cargo.toml", "src-tauri\Cargo.toml", "src-tauri\tauri.conf.json",
    "frontend\package.json", "frontend\package-lock.json", "frontend\src\App.tsx",
    ".gitignore", ".github\workflows\ci.yml"
)
foreach ($relative in $required) {
    if (-not (Test-Path -LiteralPath (Join-Path $githubDir $relative))) {
        throw "release/github is missing required file: $relative"
    }
}

$portableSize = (Get-ChildItem -LiteralPath $portableDir -Recurse -File | Measure-Object Length -Sum).Sum
$githubSize = (Get-ChildItem -LiteralPath $githubDir -Recurse -File | Measure-Object Length -Sum).Sum
$portableCount = (Get-ChildItem -LiteralPath $portableDir -Recurse -File | Measure-Object).Count
$githubCount = (Get-ChildItem -LiteralPath $githubDir -Recurse -File | Measure-Object).Count

Write-Host ""
Write-Host "Portable: $portableDir"
Write-Host "  files: $portableCount, bytes: $portableSize"
Write-Host "  BinScope.exe SHA-256: $exeHash"
Write-Host "  ZIP: $zipPath ($((Get-Item -LiteralPath $zipPath).Length) bytes)"
Write-Host "  ZIP SHA-256: $zipHash"
Write-Host "GitHub:   $githubDir"
Write-Host "  files: $githubCount, bytes: $githubSize"
Write-Host ""
Write-Host "Staging complete."
