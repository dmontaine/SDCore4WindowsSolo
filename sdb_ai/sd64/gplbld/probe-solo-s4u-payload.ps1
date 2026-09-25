# probe-solo-s4u-payload.ps1 - what SOLO 1(a)'s scheduled task runs.  Started by
# probe-solo-s4u.ps1, never by hand.  It reports the context it finds itself in
# and proves it can listen and answer, then exits.  powershell.exe imports
# USER32, which is the point: sdtlsrelay.c:104-118 records a process in a bare
# S4U session-0 logon dying before main() (0xC0000142) when USER32 cannot reach
# a window station.  If this runs at all, a task's logon does not have that trap.

param(
    [Parameter(Mandatory = $true)] [string] $Out,
    [Parameter(Mandatory = $true)] [int]    $Port
)

$lines = New-Object System.Collections.ArrayList
function Note([string] $s) { [void]$lines.Add($s) }

try {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $groups = @($id.Groups | ForEach-Object { $_.Value })
    Note ('user            : ' + $id.Name)
    Note ('sid             : ' + $id.User.Value)
    Note ('session         : ' + (Get-Process -Id $PID).SessionId)
    Note ('impersonation   : ' + $id.ImpersonationLevel)
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    Note ('admin role      : ' + $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
    $logon = @{ 'S-1-5-2' = 'NETWORK'; 'S-1-5-3' = 'BATCH'; 'S-1-5-4' = 'INTERACTIVE'; 'S-1-5-6' = 'SERVICE'; 'S-1-5-14' = 'REMOTE INTERACTIVE' }
    Note ('logon sids      : ' + ((@($logon.Keys | Where-Object { $groups -contains $_ } | ForEach-Object { $logon[$_] })) -join ','))
    Note ('integrity       : ' + ((@($groups | Where-Object { $_ -like 'S-1-16-*' })) -join ','))
    Note ('USERPROFILE     : ' + $env:USERPROFILE)
    Note ('profile exists  : ' + (Test-Path -LiteralPath $env:USERPROFILE))

    $w = Join-Path (Split-Path -Parent $Out) 'write-test.txt'
    [IO.File]::WriteAllText($w, 'written by the S4U task')
    Note ('write in profile: ' + ([IO.File]::ReadAllText($w) -eq 'written by the S4U task'))

    $l = New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback, $Port)
    $l.Start()
    Note ('listening       : 127.0.0.1:' + $Port)
    [IO.File]::WriteAllText($Out + '.ready', 'ready')
    $t = $l.AcceptTcpClientAsync()
    if ($t.Wait(30000)) {
        $c = $t.Result
        $s = $c.GetStream()
        $r = New-Object IO.StreamReader($s)
        $wr = New-Object IO.StreamWriter($s)
        $got = $r.ReadLine()
        $wr.WriteLine('hello-from-s4u-task')
        $wr.Flush()
        Note ('accepted, got   : ' + $got)
        $c.Close()
    } else {
        Note 'accept          : TIMED OUT after 30 s'
    }
    $l.Stop()
    Note 'DONE'
} catch {
    Note ('ERROR           : ' + $_.Exception.GetType().FullName + ': ' + $_.Exception.Message)
}
[IO.File]::WriteAllLines($Out, [string[]]$lines.ToArray())
