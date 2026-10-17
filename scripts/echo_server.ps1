param([int]$Port = 8099)

# Tiny TCP echo server used by smoke_test.ps1.
$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $Port)
$listener.Start()
while ($true) {
    $client = $listener.AcceptTcpClient()
    $stream = $client.GetStream()
    $buffer = New-Object byte[] 4096
    try {
        while (($n = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $stream.Write($buffer, 0, $n)
        }
    } catch { }
    finally { $client.Close() }
}
