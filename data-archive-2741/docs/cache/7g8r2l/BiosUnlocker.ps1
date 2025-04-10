# ⚠️ Run as Administrator to fully restore system settings

Write-Host "[!] Starting recovery process..." -ForegroundColor Cyan

# --- RE-ENABLE USB ---
reg add "HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR" /v Start /t REG_DWORD /d 3 /f

# --- RESTORE BOOT SETTINGS ---
bcdedit /set {current} recoveryenabled Yes
bcdedit /set {current} advancedoptions true
bcdedit /set {current} bootstatuspolicy DisplayAllFailures
bcdedit /deletevalue {globalsettings} preventbootfromnetwork
bcdedit /deletevalue {globalsettings} preventbootfromexternalmedia

# --- RE-ENABLE BIOS/UEFI UI ---
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableFirmwareUI /f

# --- ENABLE TASK MANAGER, REGEDIT, CMD ---
reg delete HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System /v DisableTaskMgr /f
reg delete HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System /v DisableRegistryTools /f
reg delete HKCU\Software\Policies\Microsoft\Windows\System /v DisableCMD /f

# --- ENABLE SHIFT+RESTART ---
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v DisableLogonShiftRestart /f

# --- ENABLE CONTROL PANEL / SETTINGS ---
reg delete HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer /v NoControlPanel /f
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v SettingsPageVisibility /f

# --- RE-ENABLE WINDOWS DEFENDER ---
Try {
    Set-MpPreference -DisableRealtimeMonitoring $false -Force
    Start-Service -Name WinDefend -ErrorAction SilentlyContinue
} Catch {}

reg delete "HKLM\Software\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /f

# --- REMOVE PERSISTENT SCRIPT FROM SYSTEM32 ---
$scriptPath = "C:\Windows\System32\secureboot.ps1"
If (Test-Path $scriptPath) {
    Remove-Item -Path $scriptPath -Force -ErrorAction SilentlyContinue
    Write-Host "[✓] Removed secureboot.ps1 from System32"
}

# --- REMOVE TASK SCHEDULER ENTRY ---
schtasks /delete /tn "SecureBootLock" /f

# --- REMOVE RUN KEY PERSISTENCE ---
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v SecureBootLock /f

# --- REMOVE WMI PERSISTENCE ---
$filterName = "SecureBootWMI"
$consumerName = "SecureBootConsumer"

# Remove filter
Get-WmiObject -Namespace root\subscription -Class __EventFilter -Filter "Name='$filterName'" -ErrorAction SilentlyContinue | Remove-WmiObject -ErrorAction SilentlyContinue

# Remove consumer
Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer -Filter "Name='$consumerName'" -ErrorAction SilentlyContinue | Remove-WmiObject -ErrorAction SilentlyContinue

# Remove bindings
Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding | Where-Object {
    $_.Filter -like "*$filterName*" -or $_.Consumer -like "*$consumerName*"
} | Remove-WmiObject -ErrorAction SilentlyContinue

Write-Host "`n[✔] System has been restored to normal." -ForegroundColor Green
Write-Host "    > Reboot recommended." -ForegroundColor Yellow
