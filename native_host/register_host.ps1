$HostName = "com.incognito_tab_saver.backup_agent"
$ManifestPath = "$PSScriptRoot\host_manifest.json"
$BatPath = "$PSScriptRoot\extension_backup_agent.bat"

# Ensure host_manifest.json contains the correct absolute path on this machine
$manifest = Get-Content $ManifestPath -Raw | ConvertFrom-Json
$manifest.path = $BatPath
$manifest | ConvertTo-Json -Depth 5 | Set-Content $ManifestPath -Encoding UTF8

$RegistryPaths = @(
    "HKCU:\Software\Google\Chrome\NativeMessagingHosts\$HostName",
    "HKCU:\Software\BraveSoftware\Brave-Browser\NativeMessagingHosts\$HostName"
)

foreach ($regPath in $RegistryPaths) {
    if (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }
    Set-ItemProperty -Path $regPath -Name "(Default)" -Value $ManifestPath
    Write-Host "Registered NMH at: $regPath -> $ManifestPath"
}
Write-Host "Registration complete!"

