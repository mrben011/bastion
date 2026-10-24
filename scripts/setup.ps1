# One-command local test environment for Windows PowerShell. Requires Docker Desktop.
# Usage: .\scripts\setup.ps1 [-AdminEmail you@example.com]
param([string]$AdminEmail = "admin@example.com")
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")
$OrgName = "Demo Organization"

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { throw "Docker is not installed. Get Docker Desktop: https://docs.docker.com/get-docker/" }

function New-Secret([int]$bytes = 24) {
  $b = New-Object byte[] $bytes
  [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
  ([Convert]::ToBase64String($b)) -replace '[/+=]', ''
}

if (Test-Path .env) { Write-Host "Keeping your existing .env" } else {
  $fb = New-Object byte[] 32
  [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($fb)
  $fernet = ([Convert]::ToBase64String($fb)).Replace('+', '-').Replace('/', '_')
  @"
DB_OWNER_PASSWORD=$(New-Secret)
DB_APP_PASSWORD=$(New-Secret)
FIELD_ENCRYPTION_KEY=$fernet
COOKIE_SECURE=false
ALLOWED_ORIGIN=http://localhost:8080
"@ | Set-Content -Encoding ascii .env
}

Write-Host "Building and starting (the first run takes a few minutes)..."
docker compose up -d --build

Write-Host "Waiting for the API..."
$ready = $false
for ($i = 0; $i -lt 90 -and -not $ready; $i++) {
  try { Invoke-WebRequest -UseBasicParsing http://localhost:8080/api/readyz | Out-Null; $ready = $true } catch { Start-Sleep 2 }
}
if (-not $ready) { throw "API did not become ready. Run: docker compose logs api migrate" }

$AdminPw = New-Secret 18
$DemoPw = New-Secret 18
docker compose run --rm -T -e BASTION_BOOTSTRAP_PASSWORD=$AdminPw migrate python -m app.cli bootstrap --org-name $OrgName --admin-email $AdminEmail
docker compose run --rm -T -e BASTION_DEMO_PASSWORD=$DemoPw migrate python -m app.cli seed-demo --org-name $OrgName

@"
Open:        http://localhost:8080
Admin:       $AdminEmail
Password:    $AdminPw
(you will be asked to set up an authenticator app on first sign-in)

Sample users (temporary password, must be changed at first sign-in):
  analyst.demo@example.com
  responder.demo@example.com
  auditor.demo@example.com
Temporary password: $DemoPw
"@ | Set-Content .local-credentials.txt

Write-Host ""
Get-Content .local-credentials.txt
Write-Host "`nSaved to .local-credentials.txt (keep it private). Stop with: docker compose down. Wipe everything with: docker compose down -v"
