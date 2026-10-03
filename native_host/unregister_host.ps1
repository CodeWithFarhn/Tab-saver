$HostName = "com.incognito_tab_saver.backup_agent"

$RegistryPaths = @(
    "HKCU:\Software\Google\Chrome\NativeMessagingHosts\$HostName",
    "HKCU:\Software\BraveSoftware\Brave-Browser\NativeMessagingHosts\$HostName"
)

foreach ($regPath in $RegistryPaths) {
    if (Test-Path $regPath) {
        Remove-Item -Path $regPath -Recurse -Force
        Write-Host "Unregistered NMH at: $regPath"
    }
}
Write-Host "Unregistration complete!"
