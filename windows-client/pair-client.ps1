$deviceName = $env:COMPUTERNAME

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

$body = @{
    deviceName = $deviceName
} | ConvertTo-Json

Write-Host ""
Write-Host "================================"
Write-Host "       PHONE UNLOCK PAIRING"
Write-Host "================================"
Write-Host ""
Write-Host "PC:"
Write-Host $deviceName
Write-Host ""

try {
    $response = Invoke-RestMethod `
        -Uri "https://localhost:3000/pairing/create" `
        -Method POST `
        -ContentType "application/json" `
        -Body $body
}
catch {
    Write-Host "ERROR: Nepodarilo se vytvorit pairing code."
    Write-Host ""
    Write-Host $_.Exception.Message
    exit 1
}

Write-Host "PAIRING CODE:"
Write-Host $response.code
Write-Host ""
Write-Host "Platnost kodu: 5 minut"
Write-Host ""
Write-Host "Na telefonu otevri:"
Write-Host "https://10.0.32.162:3000/pair"
Write-Host ""
Write-Host "Zadej kod na telefonu."
Write-Host ""
Write-Host "Cekam na sparovani..."
Write-Host ""

while ($true) {

    Start-Sleep -Seconds 2

    try {

        $encodedDeviceName =
            [uri]::EscapeDataString($deviceName)

        $pair = Invoke-RestMethod `
            -Uri "https://localhost:3000/pairing/device/$encodedDeviceName" `
            -Method GET

        Write-Host ""
        Write-Host "================================"
        Write-Host "       DEVICE PAIRED"
        Write-Host "================================"
        Write-Host ""

        Write-Host "PC:"
        Write-Host $pair.deviceName

        Write-Host "Phone:"
        Write-Host $pair.phoneName

        Write-Host "Pair ID:"
        Write-Host $pair.pairId

        Write-Host ""
        Write-Host "Pair Secret: ********"
        Write-Host ""

        $configPath = "$PSScriptRoot\pairing.json"

        $config = @{
            pairId = $pair.pairId
            pairSecret = $pair.pairSecret
            deviceName = $pair.deviceName
            phoneName = $pair.phoneName
        } | ConvertTo-Json

        $config | Set-Content `
            -Path $configPath `
            -Encoding UTF8

        Write-Host "Pairing ulozeno do:"
        Write-Host $configPath
        Write-Host ""

        break
    }
    catch {
        Write-Host "`rCekam na telefon..." -NoNewline
    }
}