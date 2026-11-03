



param(
    [int]$LargeMb = 64
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

Write-Host "Building release benchmark..."
cargo build --release -p binscope-core --example benchmark
if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }

$exe = Join-Path $root "target\release\examples\benchmark.exe"
$log = Join-Path $env:TEMP "binscope-benchmark.out"
if (Test-Path $log) { Remove-Item $log -Force }

$proc = Start-Process -FilePath $exe -ArgumentList "$LargeMb" -PassThru -NoNewWindow -RedirectStandardOutput $log
$peak = 0L
$start = Get-Date
while (-not $proc.HasExited) {
    try {
        $proc.Refresh()
        if ($proc.WorkingSet64 -gt $peak) { $peak = $proc.WorkingSet64 }
    } catch { }
    Start-Sleep -Milliseconds 40
}
$elapsed = (Get-Date) - $start
Get-Content $log
Write-Host ""
Write-Host ("Peak working set: {0:N1} MiB" -f ($peak / 1MB))
Write-Host ("Wall clock:       {0:N2} s" -f $elapsed.TotalSeconds)
Write-Host "Note: wall-clock and RSS include process startup and the synthetic buffer construction."
