# ductei-sync v3 deploy (or -Rollback). Reads exe, state dir and peer from the
# ductei-sync-serve / ductei-sync-push scheduled tasks, so the same script runs
# on xing-pc and xing-laptop. Every check runs BEFORE anything is stopped.
param([string]$Source = 'D:\ATRIUM\DUCTEI\target\release\ductei-sync.exe', [switch]$Rollback)
$ErrorActionPreference = 'Stop'
$expected = 'D6A28AE905E7DFF54A7B821698346FBE24CA3EC4802F0D50FDB3699956965C4B'

function TaskLine($name) {
    $t = Get-ScheduledTask -TaskName $name
    "$($t.Actions[0].Execute) $($t.Actions[0].Arguments)"
}
$serveLine = TaskLine 'ductei-sync-serve'
$pushLine = TaskLine 'ductei-sync-push'
$exe = [regex]::Match($serveLine, '([A-Za-z]:\\[^"]*?ductei-sync\.exe)').Groups[1].Value
$state = [regex]::Match($serveLine, 'serve\s+"?([^"]+?)"?\s+--').Groups[1].Value
$peer = [regex]::Match($pushLine, '--peer\s+"?([^"\s]+)').Groups[1].Value
if (-not $exe -or -not $state -or -not $peer) { throw "could not parse tasks: exe=[$exe] state=[$state] peer=[$peer]" }
$legacy = Join-Path $state 'qfltl\known_peers'
$pin = Join-Path $legacy (($peer -replace '[^\p{L}\p{N}\-\.]', '_') + '.pub')
$bak = "$exe.v2.bak"
"host=$env:COMPUTERNAME exe=$exe"
"state=$state peer=$peer"

function Stop-Sync {
    Stop-ScheduledTask -TaskName ductei-sync-push -ErrorAction SilentlyContinue
    Stop-ScheduledTask -TaskName ductei-sync-serve -ErrorAction SilentlyContinue
    Get-Process ductei-sync -ErrorAction SilentlyContinue | Stop-Process -Force
    Start-Sleep -Seconds 1
}
function Start-Sync {
    Start-ScheduledTask -TaskName ductei-sync-serve
    Start-ScheduledTask -TaskName ductei-sync-push
    Start-Sleep -Seconds 4
    "running: " + ((Get-Process ductei-sync -ErrorAction SilentlyContinue | ForEach-Object Id) -join ', ')
    foreach ($line in $serveLine, $pushLine) {
        $log = [regex]::Match($line, '>>\s*"([^"]+)"').Groups[1].Value
        if ($log -and (Test-Path $log)) { "--- $log"; Get-Content $log -Tail 3 }
    }
}

if ($Rollback) {
    if (-not (Test-Path $bak)) { throw "no backup at $bak" }
    Stop-Sync
    Copy-Item $bak $exe -Force
    if (Test-Path "$legacy.v2-retired") { Rename-Item "$legacy.v2-retired" 'known_peers' }
    Start-Sync
    'ROLLED BACK to v2'
    return
}

$h = (Get-FileHash $Source -Algorithm SHA256).Hash
if ($h -ne $expected) { throw "binary hash mismatch: $h" }
if (-not (Test-Path $pin)) { throw "legacy pin not found: $pin" }

Stop-Sync
if (-not (Test-Path $bak)) { Copy-Item $exe $bak }
Copy-Item $Source $exe -Force
& $exe key-pin $state --role server --peer $peer --file $pin
if ($LASTEXITCODE -ne 0) { throw 'key-pin server failed (run with -Rollback)' }
& $exe key-pin $state --role client --peer ($peer.Split(':')[0]) --file $pin
if ($LASTEXITCODE -ne 0) { throw 'key-pin client failed (run with -Rollback)' }
Rename-Item $legacy 'known_peers.v2-retired'
Start-Sync
'DEPLOYED v3'
