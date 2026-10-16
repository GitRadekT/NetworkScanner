<#
    NetworkScanner - skaner sieci lokalnej: IP, MAC, producent, nazwa hosta

    Uruchomienie z GitHuba (autowykrywanie sieci):
        irm https://raw.githubusercontent.com/TWOJ_LOGIN/NetworkScanner/main/NetworkScanner.ps1 | iex

    Z parametrami:
        & ([scriptblock]::Create((irm https://raw.githubusercontent.com/TWOJ_LOGIN/NetworkScanner/main/NetworkScanner.ps1))) -Network 10.0.0.0/22 -Csv C:\Temp\wynik.csv

    Lokalnie:
        powershell -ExecutionPolicy Bypass -File NetworkScanner.ps1 -Network 192.168.1.0/24
#>
param(
    [string]$Network   = "",    # puste = autowykrywanie ; np. 192.168.1.0/24, 10.0.0.0/22, 10.0.0.0/255.255.252.0
    [int]   $Timeout   = 500,   # timeout pinga w ms
    [int]   $BatchSize = 256,   # ile pingów naraz
    [string]$Csv       = ""     # np. C:\Temp\wynik.csv ; puste = bez zapisu
)

& {
    function IpToInt([string]$ip) {
        $b = ([Net.IPAddress]::Parse($ip)).GetAddressBytes(); [Array]::Reverse($b)
        [int64][BitConverter]::ToUInt32($b, 0)
    }
    function IntToIp([int64]$n) {
        $b = [BitConverter]::GetBytes([uint32]$n); [Array]::Reverse($b)
        (New-Object Net.IPAddress (, $b)).ToString()
    }
    function MaskToPrefix([string]$mask) {
        $m = IpToInt $mask; $p = 0
        for ($k = 31; $k -ge 0; $k--) { if ($m -band ([int64]1 -shl $k)) { $p++ } else { break } }
        $p
    }

    # --- Autowykrywanie sieci hosta (.NET) ---
    $net_ = $Network
    if (-not $net_) {
        $cands = foreach ($nic in [Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
            if ($nic.OperationalStatus -ne 'Up') { continue }
            if ($nic.NetworkInterfaceType -in 'Loopback', 'Tunnel') { continue }
            $props = $nic.GetIPProperties()
            $gw = $props.GatewayAddresses |
                Where-Object { $_.Address.AddressFamily -eq 'InterNetwork' -and $_.Address.ToString() -ne '0.0.0.0' } |
                Select-Object -First 1
            foreach ($ua in $props.UnicastAddresses) {
                if ($ua.Address.AddressFamily -ne 'InterNetwork') { continue }
                $ipS = $ua.Address.ToString()
                if ($ipS -like '169.254.*' -or $ipS -like '127.*') { continue }
                $p = if ($ua.IPv4Mask -and $ua.IPv4Mask.ToString() -ne '0.0.0.0') { MaskToPrefix $ua.IPv4Mask.ToString() } else { 24 }
                [pscustomobject]@{
                    Interfejs = $nic.Name
                    Opis      = $nic.Description
                    IP        = $ipS
                    Prefix    = $p
                    Brama     = if ($gw) { $gw.Address.ToString() } else { "" }
                    Wirtualny = [bool]($nic.Description -match 'Hyper-V|VMware|VirtualBox|Virtual|TAP-|WSL|vEthernet')
                }
            }
        }

        if (-not $cands) {
            Write-Warning "Nie znaleziono żadnej aktywnej karty z adresem IPv4. Podaj -Network ręcznie."
            return
        }

        $cands = @($cands | Sort-Object @{ e = { [bool]$_.Brama }; Descending = $true }, @{ e = { $_.Wirtualny } })
        $addr  = $cands[0]

        if ($cands.Count -gt 1) {
            Write-Host "`nZnalezione karty sieciowe (wybrana pierwsza):" -ForegroundColor Cyan
            $cands | Format-Table Interfejs, IP, Prefix, Brama, Wirtualny, Opis -AutoSize | Out-Host
        }

        $p     = [int]$addr.Prefix
        $sz    = [int64][math]::Pow(2, 32 - $p)
        $i     = IpToInt $addr.IP
        $net_  = "{0}/{1}" -f (IntToIp ($i - ($i % $sz))), $p
        $maskT = IntToIp ([int64][math]::Pow(2, 32) - $sz)

        Write-Host ""
        Write-Host "Wykryta sieć hosta:" -ForegroundColor Cyan
        Write-Host "  Interfejs : $($addr.Interfejs)  ($($addr.Opis))"
        Write-Host "  Adres IP  : $($addr.IP)"
        Write-Host "  Maska     : $maskT (/$p)"
        Write-Host "  Brama     : $($addr.Brama)"
        Write-Host "  Sieć      : $net_" -ForegroundColor Green
        Write-Host ""
    }

    # --- Ustalenie zakresu ---
    $ipPart, $maskPart = $net_ -split '/'
    if (-not $maskPart) { $maskPart = '24' }
    if ($maskPart -match '\.') { $prefix = MaskToPrefix $maskPart } else { $prefix = [int]$maskPart }
    if ($prefix -lt 8 -or $prefix -gt 32) { Write-Warning "Nieprawidłowa maska: $maskPart (dozwolone /8 - /32)"; return }

    $size  = [int64][math]::Pow(2, 32 - $prefix)
    $ipInt = IpToInt $ipPart
    $net   = $ipInt - ($ipInt % $size)
    $bcast = $net + $size - 1
    if ($prefix -ge 31) { $first = $net; $last = $bcast } else { $first = $net + 1; $last = $bcast - 1 }
    $count = $last - $first + 1

    Write-Host ("Skanuję {0}/{1}: {2} - {3} ({4} adresów)" -f (IntToIp $net), $prefix, (IntToIp $first), (IntToIp $last), $count)
    if ($count -gt 65534) {
        if ((Read-Host "To duży zakres i potrwa długo. Kontynuować? (t/n)") -ne 't') { return }
    }

    # --- Baza producentów (Wireshark manuf), pobierana raz na 30 dni ---
    $ouiFile = Join-Path $env:LOCALAPPDATA "manuf.txt"
    if (-not (Test-Path $ouiFile) -or (Get-Item $ouiFile).LastWriteTime -lt (Get-Date).AddDays(-30)) {
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest "https://www.wireshark.org/download/automated/data/manuf" `
                -OutFile $ouiFile -UseBasicParsing
        } catch { Write-Warning "Nie udało się pobrać bazy producentów: $($_.Exception.Message)" }
    }

    $vendors = @{}
    if (Test-Path $ouiFile) {
        foreach ($line in [IO.File]::ReadLines($ouiFile)) {
            if ($line -match '^\s*(#|$)') { continue }
            $f = $line -split "`t"
            if ($f.Count -lt 2) { continue }
            $name = if ($f.Count -ge 3 -and $f[2].Trim()) { $f[2].Trim() } else { $f[1].Trim() }
            if ($f[0] -match '^(.+)/(\d+)$') {
                $hex = ($matches[1] -replace '[:\-\.]', '').Substring(0, [int]($matches[2] / 4))
            } else {
                $hex = $f[0].Trim() -replace '[:\-\.]', ''
            }
            $vendors[$hex.ToUpper()] = $name
        }
    }

    function Get-Vendor([string]$mac) {
        $hex = ($mac -replace '[-:]', '').ToUpper()
        if ($hex.Length -lt 6) { return "" }
        if ([Convert]::ToByte($hex.Substring(0, 2), 16) -band 2) { return "(losowy/prywatny MAC)" }
        foreach ($len in 9, 7, 6) {
            $key = $hex.Substring(0, $len)
            if ($vendors.ContainsKey($key)) { return $vendors[$key] }
        }
        ""
    }

    # --- 1. Ping w paczkach ---
    $pingOk = @{}
    for ($start = $first; $start -le $last; $start += $BatchSize) {
        $end = [math]::Min($start + $BatchSize - 1, $last)
        $batch = for ($n = $start; $n -le $end; $n++) {
            $ip = IntToIp $n
            [pscustomobject]@{ IP = $ip; Task = (New-Object Net.NetworkInformation.Ping).SendPingAsync($ip, $Timeout) }
        }
        try { [Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($batch.Task)) } catch {}
        foreach ($b in $batch) {
            if ($b.Task.Status -eq 'RanToCompletion' -and $b.Task.Result.Status -eq 'Success') { $pingOk[$b.IP] = $true }
        }
        $done = $end - $first + 1
        Write-Progress -Activity "Ping" -Status "$done / $count" -PercentComplete ($done / $count * 100)
    }
    Write-Progress -Activity "Ping" -Completed

    # --- 2. Tablica ARP (Get-NetNeighbor + arp -a jako zapas) ---
    $arp = @{}
    Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object {
            $_.LinkLayerAddress -and
            $_.State -notin 'Unreachable', 'Incomplete' -and
            $_.LinkLayerAddress -notin '00-00-00-00-00-00', 'FF-FF-FF-FF-FF-FF'
        } |
        ForEach-Object {
            $n = IpToInt $_.IPAddress
            if ($n -ge $first -and $n -le $last) { $arp[$_.IPAddress] = $_.LinkLayerAddress }
        }

    arp -a | ForEach-Object {
        if ($_ -match '^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})\s') {
            $ipA = $matches[1]; $macA = $matches[2].ToUpper()
            if ($macA -ne 'FF-FF-FF-FF-FF-FF' -and -not $arp.ContainsKey($ipA)) {
                $n = IpToInt $ipA
                if ($n -ge $first -and $n -le $last) { $arp[$ipA] = $macA }
            }
        }
    }

    $ips = @($arp.Keys) + @($pingOk.Keys) | Sort-Object -Unique

    # --- 3. Nazwy hostów (DNS równolegle, max 10 s) ---
    $dns = @{}
    foreach ($ip in $ips) { $dns[$ip] = [Net.Dns]::GetHostEntryAsync($ip) }
    if ($dns.Count) { try { [void][Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($dns.Values), 10000) } catch {} }

    # --- 4. Wyniki ---
    $wyniki = foreach ($ip in $ips) {
        $t    = $dns[$ip]
        $name = if ($t.Status -eq 'RanToCompletion') { $t.Result.HostName } else { "" }
        $mac  = $arp[$ip]
        [pscustomobject]@{
            IP        = $ip
            MAC       = if ($mac) { $mac } else { "(poza siecią lokalną)" }
            Producent = if ($mac) { Get-Vendor $mac } else { "" }
            Hostname  = $name
            Ping      = [bool]$pingOk[$ip]
        }
    }
    $wyniki = @($wyniki | Sort-Object { [version]$_.IP })

    $wyniki | Format-Table -AutoSize
    Write-Host "Znaleziono urządzeń: $($wyniki.Count)"

    if ($Csv) {
        $wyniki | Export-Csv $Csv -NoTypeInformation -Encoding UTF8
        Write-Host "Zapisano do: $Csv"
    }
}
