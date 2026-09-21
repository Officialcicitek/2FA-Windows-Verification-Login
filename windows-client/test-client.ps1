$configPath = "$PSScriptRoot\pairing.json"

if (-not (Test-Path $configPath)) {
    Write-Host "ERROR: pairing.json nebyl nalezen."
    Write-Host "Nejdriv spust pair-client.ps1."
    exit 1
}

$config = Get-Content $configPath -Raw | ConvertFrom-Json

$deviceName = $config.deviceName
$pairId = $config.pairId
$pairSecret = $config.pairSecret

if (-not $pairSecret) {
    Write-Host "ERROR: pairing.json neobsahuje pairSecret."
    Write-Host "Musis zarizeni znovu sparovat."
    exit 1
}

# Trust self-signed HTTPS certificate
if (-not ([System.Management.Automation.PSTypeName]'TrustAllCertsPolicy').Type) {
    Add-Type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;

public class TrustAllCertsPolicy : ICertificatePolicy
{
    public bool CheckValidationResult(
        ServicePoint srvPoint,
        X509Certificate certificate,
        WebRequest request,
        int certificateProblem)
    {
        return true;
    }
}
"@
}

[System.Net.ServicePointManager]::CertificatePolicy =
    New-Object TrustAllCertsPolicy

# Generate 32-byte random challenge
$randomBytes = New-Object byte[] 32

$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$rng.GetBytes($randomBytes)
$rng.Dispose()

$challenge = (
    $randomBytes |
    ForEach-Object {
        $_.ToString("x2")
    }
) -join ""

$body = @{
    deviceName = $deviceName
    pairId = $pairId
    pairSecret = $pairSecret
    challenge = $challenge
} | ConvertTo-Json

$headers = @{
    Authorization = "Bearer $pairSecret"
}

Write-Host ""
Write-Host "================================"
Write-Host "       PHONE UNLOCK"
Write-Host "================================"
Write-Host ""
Write-Host "Device: $deviceName"
Write-Host "Phone:  $($config.phoneName)"
Write-Host ""
Write-Host "Creating secure login request..."
Write-Host ""

try {
    $response = Invoke-RestMethod `
        -Uri "https://localhost:3000/auth/request" `
        -Method POST `
        -ContentType "application/json" `
        -Headers $headers `
        -Body $body
}
catch {
    Write-Host ""
    Write-Host "ERROR: Nepodarilo se vytvorit login request."
    Write-Host ""
    Write-Host $_.Exception.Message
    Write-Host ""
    exit 1
}

$requestId = $response.requestId

Write-Host "Request: $requestId"
Write-Host ""
Write-Host "Waiting for phone approval..."
Write-Host ""

while ($true) {

    Start-Sleep -Seconds 1

    try {

        $status = Invoke-RestMethod `
            -Uri "https://localhost:3000/auth/request/$requestId" `
            -Method GET `
            -Headers $headers

        Write-Host "`rStatus: $($status.status)    " -NoNewline

        if ($status.status -eq "approved") {

            Write-Host ""
            Write-Host ""
            Write-Host "================================"
            Write-Host "        LOGIN APPROVED"
            Write-Host "================================"
            Write-Host ""
            Write-Host "Phone approved the login."
            Write-Host ""

            break
        }

        if ($status.status -eq "denied") {

            Write-Host ""
            Write-Host ""
            Write-Host "================================"
            Write-Host "         LOGIN DENIED"
            Write-Host "================================"
            Write-Host ""
            Write-Host "Phone denied the login."
            Write-Host ""

            break
        }

        if ($status.status -eq "expired") {

            Write-Host ""
            Write-Host ""
            Write-Host "================================"
            Write-Host "        LOGIN EXPIRED"
            Write-Host "================================"
            Write-Host ""
            Write-Host "Phone did not approve the login in time."
            Write-Host ""

            break
        }

    }
    catch {

        Write-Host ""
        Write-Host ""
        Write-Host "ERROR: Chyba pri kontrole statusu."
        Write-Host ""
        Write-Host $_.Exception.Message
        Write-Host ""

        break
    }
}