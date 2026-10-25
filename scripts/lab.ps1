param(
  [Parameter(Position=0)][ValidateSet('install','start','stop','restart','status','logs','verify','passwords','update')][string]$Action='install',
  [ValidateSet('auto','postgres','mysql','sqlite')][string]$Database='auto',
  [int]$Port=8787,
  [switch]$ShowPasswords
)
$ErrorActionPreference='Stop'
$Root=Split-Path $PSScriptRoot -Parent
Set-Location $Root

function New-LabSecret {
  $bytes=New-Object byte[] 32
  $rng=[Security.Cryptography.RandomNumberGenerator]::Create()
  try {$rng.GetBytes($bytes)} finally {$rng.Dispose()}
  ([BitConverter]::ToString($bytes)).Replace('-','').ToLowerInvariant()
}
function Read-LabEnv {
  $values=@{}
  if(Test-Path -LiteralPath '.env'){
    foreach($line in Get-Content -LiteralPath '.env'){
      if($line -match '^([^#=]+)=(.*)$'){$values[$matches[1]]=$matches[2]}
    }
  }
  $values
}
function Add-EnvValue([string]$Name,[string]$Value,[hashtable]$Values){
  if(-not $Values.ContainsKey($Name)){Add-Content -Encoding ascii -LiteralPath '.env' -Value "$Name=$Value";$Values[$Name]=$Value}
}
function Require-Docker {
  if(-not (Get-Command docker -ErrorAction SilentlyContinue)){throw 'Docker Desktop is not installed or docker is not on PATH.'}
  docker info --format '{{.ServerVersion}}' | Out-Null
  if($LASTEXITCODE -ne 0){throw 'Start Docker Desktop with Linux containers, then retry.'}
  docker compose version | Out-Null
  if($LASTEXITCODE -ne 0){throw 'Docker Compose v2 is required.'}
}
function Resolve-Database([hashtable]$Values){
  if($Database -ne 'auto'){return $Database}
  if($Values.ContainsKey('LAB_DATABASE')){return $Values.LAB_DATABASE}
  'postgres'
}
function Compose-File([string]$Choice){
  switch($Choice){'mysql'{'compose.mysql.yaml'}'sqlite'{'compose.sqlite.yaml'}default{'compose.yaml'}}
}
function Invoke-Compose([string]$File,[string[]]$Arguments){
  & docker compose -f $File @Arguments
  if($LASTEXITCODE -ne 0){throw "Docker Compose failed: $($Arguments -join ' ')"}
}
function Test-Lab([hashtable]$Values){
  $url="http://localhost:$($Values.APP_PORT)/health"
  for($attempt=1;$attempt -le 30;$attempt++){
    try{$health=Invoke-RestMethod -Uri $url -TimeoutSec 4;if($health.status -eq 'ok'){Write-Host "Healthy: Identity API Lab $($health.version) at http://localhost:$($Values.APP_PORT)";return}}catch{}
    Start-Sleep -Seconds 2
  }
  throw "The container started but $url did not become healthy. Run: .\scripts\lab.ps1 logs"
}

Require-Docker
$envValues=Read-LabEnv
if($Action -eq 'install'){
  if($Port -lt 1024 -or $Port -gt 65535){throw 'Choose a port between 1024 and 65535.'}
  if(-not (Test-Path -LiteralPath '.env')){
    while(Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue){$Port++}
    if($Port -gt 65535){throw 'No available port was found.'}
    New-Item -ItemType File -Path '.env' | Out-Null
    $envValues=@{}
  }
  $choice=if($Database -eq 'auto'){'postgres'}else{$Database}
  Add-EnvValue 'APP_PORT' $Port $envValues
  Add-EnvValue 'GRPC_PORT' '50051' $envValues
  Add-EnvValue 'APP_BIND' '127.0.0.1' $envValues
  Add-EnvValue 'LAB_DATABASE' $choice $envValues
  Add-EnvValue 'DB_PASSWORD' (New-LabSecret) $envValues
  Add-EnvValue 'DB_ROOT_PASSWORD' (New-LabSecret) $envValues
  Add-EnvValue 'ADMIN_PASSWORD' ('Lab-'+(New-LabSecret)) $envValues
  Add-EnvValue 'DEMO_PASSWORD' ('Demo-'+(New-LabSecret)) $envValues
  Add-EnvValue 'SERVER_SIGNING_KEY' (New-LabSecret) $envValues
  Add-EnvValue 'COOKIE_SECURE' 'false' $envValues
  Add-EnvValue 'ALLOWED_HOSTS' 'localhost,127.0.0.1' $envValues
  Add-EnvValue 'ALLOW_PRIVATE_SSO' 'false' $envValues
  Add-EnvValue 'ALLOW_INSECURE_SSO' 'false' $envValues
  Add-EnvValue 'ALLOW_PRIVATE_SFTP' 'false' $envValues
  Add-EnvValue 'GRPC_ENABLED' 'true' $envValues
  Add-EnvValue 'PUBLIC_URL' "http://localhost:$($envValues.APP_PORT)" $envValues
  $choice=Resolve-Database $envValues;$file=Compose-File $choice
  Invoke-Compose -File $file -Arguments @('config','--quiet')
  Invoke-Compose -File $file -Arguments @('up','-d','--build','--wait','--wait-timeout','240')
  Test-Lab $envValues
  Write-Host 'Username: admin'
  Write-Host 'Passwords are stored only in .env. Run .\scripts\lab.ps1 passwords to display them.'
  if($ShowPasswords){$Action='passwords'}else{return}
}
$envValues=Read-LabEnv
if(-not $envValues.Count){throw 'No .env file exists. Run the install action first.'}
$choice=Resolve-Database $envValues;$file=Compose-File $choice
switch($Action){
  'start'{Invoke-Compose -File $file -Arguments @('up','-d','--wait');Test-Lab $envValues}
  'stop'{Invoke-Compose -File $file -Arguments @('stop')}
  'restart'{Invoke-Compose -File $file -Arguments @('restart');Test-Lab $envValues}
  'status'{Invoke-Compose -File $file -Arguments @('ps')}
  'logs'{Invoke-Compose -File $file -Arguments @('logs','--tail','200','-f','app')}
  'verify'{Test-Lab $envValues;& python scripts/verify_live.py;if($LASTEXITCODE -ne 0){throw 'Live acceptance verification failed.'}}
  'passwords'{Write-Host 'Admin username: admin';Write-Host "Admin password: $($envValues.ADMIN_PASSWORD)";Write-Host "Employee demo password: $($envValues.DEMO_PASSWORD)"}
  'update'{Invoke-Compose -File $file -Arguments @('up','-d','--build','--pull','--wait','--wait-timeout','240');Test-Lab $envValues}
}
