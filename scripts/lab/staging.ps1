# Staging check for the lab VM, run through Azure Run Command before any test.
# Prints the computer name and the state of the Defender for Endpoint sensor
# service (Sense), so the pipeline can confirm it's talking to the lab VM and
# that Defender is recording.

$sense = Get-Service -Name Sense -ErrorAction SilentlyContinue
$state = if ($sense) { [string]$sense.Status } else { 'Missing' }
"HOSTNAME=$env:COMPUTERNAME"
"SENSE=$state"
