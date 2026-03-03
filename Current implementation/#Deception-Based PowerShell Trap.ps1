# Deception-Based PowerShell Trap
Write-Host "Loading Secure Credentials..."
Start-Sleep -Seconds 2

# Fake Credential Dump
$adminUser = "Admin"
$adminPass = "SecurePass123!"

Write-Host "Decrypting User Credentials..."
Start-Sleep -Seconds 3
Write-Host "Username: $adminUser"
Write-Host "Password: $adminPass"

# Trap Activation - Log IP & Trigger Response
$attackerIP = (Get-NetIPAddress | Where-Object { $_.AddressFamily -eq "IPv4" }).IPAddress
Add-Content -Path "C:\Windows\System32\honeypot_log.txt" -Value "ATTACKER IP: $attackerIP - $(Get-Date)"

# Adaptive AI Response
if ((Get-Random -Minimum 1 -Maximum 10) -gt 5) {
    # Silent Lockout
    Write-Host "🛑 Unauthorized Access Detected. Locking System..."
    Start-Sleep -Seconds 5
    Stop-Computer -Force
}
else {
    # Fake Error Message
    Write-Host "Error: Credential Decryption Failed. Retrying..."
}

