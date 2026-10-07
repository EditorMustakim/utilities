<#
.SYNOPSIS
  Finds free IPv4 addresses on a local subnet (ping sweep + ARP cache check).

.EXAMPLE
  freeip.ps1 172.25.155.33/27
  freeip.ps1                      # auto-detects your subnet
  freeip.ps1 172.25.155.0/27 -Passes 3 -Csv free.csv
#>
param(
    [Parameter(Position = 0)][string]$Subnet,
    [int]$TimeoutMs = 1000,
    [int]$Passes = 2,
    [string]$Csv
)

$ErrorActionPreference = 'Stop'

function To-Num([string]$ip) {
    $b = ([System.Net.IPAddress]::Parse($ip)).GetAddressBytes()
    [Array]::Reverse($b)
    [uint64][BitConverter]::ToUInt32($b, 0)
}
function To-Ip([uint64]$n) {
    $b = [BitConverter]::GetBytes([uint32]$n)
    [Array]::Reverse($b)
    (New-Object System.Net.IPAddress -ArgumentList (, $b)).ToString()
}

# ---- Work out the subnet -------------------------------------------------
if (-not $Subnet) {
    $cfg = Get-NetIPConfiguration |
        Where-Object { $_.IPv4DefaultGateway -and $_.NetAdapter.Status -eq 'Up' } |
        Select-Object -First 1
    if (-not $cfg) { throw "Could not auto-detect a subnet. Pass one, e.g. 172.25.155.33/27" }
    $a = $cfg.IPv4Address[0]
    $Subnet = "$($a.IPAddress)/$($a.PrefixLength)"
}

$parts = $Subnet -split '/'
if ($parts.Count -ne 2) { throw "Use CIDR format, e.g. 172.25.155.33/27" }
$prefix = [int]$parts[1]
if ($prefix -lt 22 -or $prefix -gt 30) { throw "Prefix must be between /22 and /30 for this tool." }

$size    = [uint64]1 -shl (32 - $prefix)
$ipNum   = To-Num $parts[0]
$netNum  = [uint64]($ipNum - ($ipNum % $size))
$bcast   = [uint64]($netNum + $size - 1)
$first   = [uint64]($netNum + 1)
$last    = [uint64]($bcast - 1)
$hosts   = @()
for ($n = $first; $n -le $last; $n++) { $hosts += To-Ip $n }

Write-Host ""
Write-Host "Subnet    : $(To-Ip $netNum)/$prefix"
Write-Host "Usable    : $(To-Ip $first) - $(To-Ip $last)  ($($hosts.Count) addresses)"
Write-Host "Broadcast : $(To-Ip $bcast)"

# ---- This PC's addresses and gateways ------------------------------------
$local = @{}
Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    ForEach-Object { $local[$_.IPAddress] = $true }
$gateways = @{}
Get-NetIPConfiguration -ErrorAction SilentlyContinue | ForEach-Object {
    if ($_.IPv4DefaultGateway) { $gateways[$_.IPv4DefaultGateway.NextHop] = $true }
}

# ---- Ping sweep (all hosts in parallel, repeated for reliability) --------
$pingReplied = @{}
for ($p = 1; $p -le $Passes; $p++) {
    Write-Host "Ping sweep pass $p of $Passes ..."
    $jobs = @{}
    foreach ($ip in $hosts) {
        $pinger = New-Object System.Net.NetworkInformation.Ping
        $jobs[$ip] = @{ Pinger = $pinger; Task = $pinger.SendPingAsync($ip, $TimeoutMs) }
    }
    foreach ($ip in $hosts) {
        try {
            $r = $jobs[$ip].Task.GetAwaiter().GetResult()
            if ($r.Status -eq 'Success') { $pingReplied[$ip] = $true }
        } catch { }
        $jobs[$ip].Pinger.Dispose()
    }
}

# ---- ARP cache (read right after the sweep) ------------------------------
$arp = @{}
foreach ($line in (arp -a)) {
    if ($line -match '^\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}(-[0-9a-fA-F]{2}){5})\s+(\w+)') {
        $ip  = $Matches[1]
        $mac = $Matches[2].ToLower()
        if ($mac -eq 'ff-ff-ff-ff-ff-ff') { continue }
        $n = To-Num $ip
        if ($n -ge $first -and $n -le $last) { $arp[$ip] = $mac }
    }
}

# ---- Classify ------------------------------------------------------------
$taken = @()
$free  = @()
foreach ($ip in $hosts) {
    $byPing = $pingReplied.ContainsKey($ip)
    $byArp  = $arp.ContainsKey($ip)
    $isMe   = $local.ContainsKey($ip)
    if ($byPing -or $byArp -or $isMe) {
        $how = @()
        if ($isMe)   { $how += 'this PC' }
        if ($byPing) { $how += 'ping' }
        if ($byArp)  { $how += 'ARP' }
        $note = ''
        if ($gateways.ContainsKey($ip)) { $note = 'default gateway' }
        elseif ($byArp -and -not $byPing -and -not $isMe) { $note = 'live, blocks ping' }
        $taken += [pscustomobject]@{
            IP = $ip; Detected = ($how -join '+'); MAC = $arp[$ip]; Note = $note
        }
    } else {
        $free += $ip
    }
}

# ---- Report --------------------------------------------------------------
Write-Host ""
Write-Host "TAKEN ($($taken.Count)):" -ForegroundColor Yellow
$taken | Format-Table -AutoSize | Out-String | Write-Host

Write-Host "FREE CANDIDATES ($($free.Count)):" -ForegroundColor Green
Write-Host ($free -join ', ')

# Group free addresses into contiguous ranges
Write-Host ""
Write-Host "Free ranges:" -ForegroundColor Green
if ($free.Count -gt 0) {
    $nums = $free | ForEach-Object { To-Num $_ }
    $start = $nums[0]; $prev = $nums[0]
    for ($i = 1; $i -le $nums.Count; $i++) {
        if ($i -lt $nums.Count -and $nums[$i] -eq $prev + 1) { $prev = $nums[$i]; continue }
        $len = $prev - $start + 1
        if ($len -eq 1) { Write-Host "  $(To-Ip $start)" }
        else            { Write-Host "  $(To-Ip $start) - $(To-Ip $prev)   ($len addresses)" }
        if ($i -lt $nums.Count) { $start = $nums[$i]; $prev = $nums[$i] }
    }
}

Write-Host ""
Write-Host "Note: 'free' means no ping reply and no ARP entry right now. Devices that are"
Write-Host "off, asleep, or in a DHCP pool can still claim these. Check with whoever runs"
Write-Host "the network, and re-run at a different time of day before assigning one."

if ($Csv) {
    $free | ForEach-Object { [pscustomobject]@{ FreeIP = $_ } } | Export-Csv -NoTypeInformation -Path $Csv
    Write-Host "Saved free list to $Csv"
}
