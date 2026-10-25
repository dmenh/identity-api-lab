param([ValidateSet('postgres','mysql','sqlite')][string]$Database='postgres',[int]$Port=8787)
& "$PSScriptRoot\lab.ps1" install -Database $Database -Port $Port
if($LASTEXITCODE -ne 0){exit $LASTEXITCODE}
