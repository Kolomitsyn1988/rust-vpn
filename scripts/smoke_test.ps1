# Smoke test for rust-vpn: echo server <- vpn-server <- vpn-client <- SOCKS client.
# Usage: powershell -ExecutionPolicy Bypass -File scripts\smoke_test.ps1
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$cargo = Join-Path $env:USERPROFILE '.cargo\bin\cargo.exe'
if (-not (Test-Path $cargo)) { $cargo = 'cargo' }

$psk = -join (1..32 | ForEach-Object { '{0:x2}' -f (Get-Random -Minimum 0 -Maximum 256) })
$echoPort = 8099
$serverPort = 51821
$socksPort = 1081

$serverLog = Join-Path $env:TEMP 'rust-vpn-server.log'
$clientLog = Join-Path $env:TEMP 'rust-vpn-client.log'

function Wait-TcpPort([int]$port) {
    for ($i = 0; $i -lt 50; $i++) {
        try {
            $client = [System.Net.Sockets.TcpClient]::new('127.0.0.1', $port)
            $client.Close()
            return
        } catch { Start-Sleep -Milliseconds 200 }
    }
    throw "Port $port did not open in time"
}

Write-Host 'Building the workspace...'
& $cargo build --manifest-path (Join-Path $root 'Cargo.toml')
if ($LASTEXITCODE -ne 0) { throw 'Build failed' }

$echoProc = $null
$serverProc = $null
$clientProc = $null
$socks = $null

try {
    # 1. Echo server on loopback.
    $echoScript = Join-Path $PSScriptRoot 'echo_server.ps1'
    $echoProc = Start-Process powershell -WindowStyle Hidden -PassThru `
        -ArgumentList '-ExecutionPolicy', 'Bypass', '-File', "`"$echoScript`"", '-Port', "$echoPort"
    Wait-TcpPort $echoPort

    # 2. VPN server and client.
    $serverExe = Join-Path $root 'target\debug\vpn-server.exe'
    $clientExe = Join-Path $root 'target\debug\vpn-client.exe'

    $serverProc = Start-Process -FilePath $serverExe -WindowStyle Hidden `
        -ArgumentList '--listen', "127.0.0.1:$serverPort", '--psk', $psk `
        -RedirectStandardOutput $serverLog -RedirectStandardError "$serverLog.err" -PassThru
    $clientProc = Start-Process -FilePath $clientExe -WindowStyle Hidden `
        -ArgumentList '--server', "127.0.0.1:$serverPort", '--psk', $psk, '--socks-listen', "127.0.0.1:$socksPort" `
        -RedirectStandardOutput $clientLog -RedirectStandardError "$clientLog.err" -PassThru

    Wait-TcpPort $socksPort

    # 3. Speak SOCKS5 to the client and exchange bytes with the echo server.
    $socks = [System.Net.Sockets.TcpClient]::new('127.0.0.1', $socksPort)
    $stream = $socks.GetStream()
    $stream.ReadTimeout = 5000
    $stream.WriteTimeout = 5000

    $greeting = [byte[]](0x05, 0x01, 0x00)
    $stream.Write($greeting, 0, $greeting.Length)
    $reply = New-Object byte[] 2
    [void]$stream.Read($reply, 0, 2)
    if ($reply[0] -ne 0x05 -or $reply[1] -ne 0x00) { throw 'SOCKS5 greeting was refused' }

    $portHigh = [int](($echoPort -band 0xFF00) -shr 8)
    $portLow = [int]($echoPort -band 0xFF)
    $request = [byte[]](0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, $portHigh, $portLow)
    $stream.Write($request, 0, $request.Length)
    $reply = New-Object byte[] 10
    [void]$stream.Read($reply, 0, 10)
    if ($reply[1] -ne 0x00) { throw ("SOCKS5 CONNECT failed with reply code 0x{0:x2}" -f $reply[1]) }

    $payload = [System.Text.Encoding]::ASCII.GetBytes('hello')
    $stream.Write($payload, 0, $payload.Length)
    $echoed = New-Object byte[] 5
    [void]$stream.Read($echoed, 0, 5)
    $text = [System.Text.Encoding]::ASCII.GetString($echoed)
    if ($text -ne 'hello') { throw "Echo mismatch: got '$text'" }
    $socks.Close()
    $socks = $null

    Write-Host 'SMOKE TEST PASSED: bytes traveled through the encrypted tunnel.'
}
finally {
    if ($socks) { $socks.Close() }
    if ($clientProc -and -not $clientProc.HasExited) { Stop-Process -Id $clientProc.Id -Force }
    if ($serverProc -and -not $serverProc.HasExited) { Stop-Process -Id $serverProc.Id -Force }
    if ($echoProc -and -not $echoProc.HasExited) { Stop-Process -Id $echoProc.Id -Force }
}
