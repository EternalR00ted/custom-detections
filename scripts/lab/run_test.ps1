# Runs one Atomic Red Team test on the lab VM, through Azure Run Command.
#
# The command and cleanup arrive hex-encoded, exactly as the approved fire plan
# showed them. This script launches them the same way Invoke-AtomicTest does:
# powershell tests as `powershell.exe "& {command}"`, command_prompt tests as
# `cmd.exe /c command`. That keeps the command line Defender records the same
# as Atomic Red Team's own runner would produce.

param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('powershell', 'command_prompt')]
    [string]$Executor,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^([0-9a-f]{2})+$')]
    [string]$CommandHex,

    [ValidatePattern('^([0-9a-f]{2})*$')]
    [string]$CleanupHex = '',

    [ValidateRange(10, 1800)]
    [int]$TimeoutSeconds = 300
)

$ErrorActionPreference = 'Stop'

function ConvertFrom-Hex([string]$Hex) {
    if (-not $Hex) { return '' }
    $bytes = New-Object byte[] ($Hex.Length / 2)
    for ($i = 0; $i -lt $bytes.Length; $i++) {
        $bytes[$i] = [Convert]::ToByte($Hex.Substring($i * 2, 2), 16)
    }
    return [Text.Encoding]::UTF8.GetString($bytes)
}

function Invoke-Step([string]$Kind, [string]$Command, [int]$Timeout) {
    $info = New-Object System.Diagnostics.ProcessStartInfo
    if ($Kind -eq 'powershell') {
        $info.FileName = 'powershell.exe'
        $info.Arguments = '& {' + ($Command -replace '"', '\""') + '}'
    }
    else {
        $info.FileName = 'cmd.exe'
        $info.Arguments = '/c ' + (($Command.Trim()) -replace "`r?`n", ' & ')
    }
    $info.UseShellExecute = $false
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $info.CreateNoWindow = $true
    $process = [System.Diagnostics.Process]::Start($info)
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    if (-not $process.WaitForExit($Timeout * 1000)) {
        $process.Kill()
        return @{ Code = -1; Output = "Timed out after $Timeout seconds" }
    }
    return @{ Code = $process.ExitCode; Output = ($stdout.Result + $stderr.Result) }
}

$command = ConvertFrom-Hex $CommandHex
$cleanup = ConvertFrom-Hex $CleanupHex

$result = Invoke-Step $Executor $command $TimeoutSeconds
'TEST_OUTPUT_START'
([string]$result.Output).Trim()
'TEST_OUTPUT_END'
"EXITCODE=$($result.Code)"

if ($cleanup) {
    Start-Sleep -Seconds 5
    $undo = Invoke-Step $Executor $cleanup $TimeoutSeconds
    "CLEANUP_EXITCODE=$($undo.Code)"
}
