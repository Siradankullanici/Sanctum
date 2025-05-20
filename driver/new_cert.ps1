# Path to the driver file
$driverPath = ".\sanctum.sys"

# Calculate SHA256 hash of the unsigned driver file
$driverHash = (Get-FileHash $driverPath -Algorithm SHA256).Hash.ToUpper()
Write-Host "Driver SHA256 hash:" $driverHash

# Create a new self-signed certificate with ELAM OID and export to PFX
$certSubject = "CN=Sanctum ELAM Cert"
$pfxPassword = "password"
$pfxPath = ".\sanctum.pfx"

# Create the cert with ELAM EKU (1.3.6.1.4.1.311.61.4.1) and Code Signing EKU (1.3.6.1.5.5.7.3.3)
$cert = New-SelfSignedCertificate -Type Custom `
    -Subject $certSubject `
    -KeySpec Signature `
    -KeyExportPolicy Exportable `
    -HashAlgorithm SHA256 `
    -KeyLength 2048 `
    -CertStoreLocation "Cert:\LocalMachine\My" `
    -KeyUsage DigitalSignature `
    -TextExtension @("2.5.29.37={text}1.3.6.1.4.1.311.61.4.1,1.3.6.1.5.5.7.3.3")

# Export the cert as PFX
$pfxSecurePassword = ConvertTo-SecureString -String $pfxPassword -Force -AsPlainText
Export-PfxCertificate -Cert $cert -FilePath $pfxPath -Password $pfxSecurePassword

Write-Host "ELAM certificate created and exported to $pfxPath"

# ELAM registry key path
$elamKey = "HKLM:\SYSTEM\CurrentControlSet\Control\CI\ELAM"
$driverKey = "$elamKey\sanctum"

# Create ELAM base key if not exists
If (-not (Test-Path $elamKey)) {
    New-Item -Path $elamKey -Force | Out-Null
}

# Enable audit/debug logging
Set-ItemProperty -Path $elamKey -Name "AuditDebug" -Value 1 -Type DWord

# Create the driver ELAM subkey
If (-not (Test-Path $driverKey)) {
    New-Item -Path $driverKey -Force | Out-Null
}

# Convert driver hash hex string to byte array
$hashBytes = for ($i = 0; $i -lt $driverHash.Length; $i += 2) {
    [Convert]::ToByte($driverHash.Substring($i, 2), 16)
}

# EKU string and bytes (ELAM + Code Signing EKUs)
$ekuString = "1.3.6.1.4.1.311.61.4.1;1.3.6.1.5.5.7.3.3"
$ekuBytes = [System.Text.Encoding]::Unicode.GetBytes($ekuString + "`0")  # null-terminated Unicode string

# Build the MicrosoftElamCertificateInfo binary data:
$binaryData = @()
$binaryData += [BitConverter]::GetBytes(1)        # Version DWORD
$binaryData += $hashBytes                          # SHA256 hash bytes (32 bytes)
$binaryData += [BitConverter]::GetBytes(0x800C)  # EKU type DWORD
$binaryData += $ekuBytes                           # EKU string bytes (null terminated)

# Write binary data to registry as REG_BINARY
Set-ItemProperty -Path $driverKey -Name "MicrosoftElamCertificateInfo" -Value ([byte[]]$binaryData) -Type Binary

Write-Host "ELAM registry key and certificate info set successfully."
