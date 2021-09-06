####### SCA Remediations for ImageBuilder #######
####### Script Started ######

Write-Host "Status of the Setup: Maximum Log Size (KB) setting"
Write-Host "---------------------------------------------------------------------"
Write-Host "---------------------------------------------------------------------"
Write-Host "---------------------------------------------------------------------"

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows" -Name "EventLog"
New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows" -Name "LanmanWorkstation"
New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows" -Name "Defender"
New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows" -Name "Explorer"
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows" -Name "WinRM"
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows" -Name "CredentialsDelegation"
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows" -Name "PowerShell"
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows" -Name "CloudContent"
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows" -Name "Kernel DMA Protection"
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows" -Name "Connect"
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows" -Name "Windows Search"
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows" -Name "Group Policy"
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows" -Name "Onedrive"
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows" -Name "PreviewBuilds"
New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows" -Name "CredUI"
New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows" -Name "Personalization"

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM" -Name "Client"
New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\Defender" -Name "Windows Defender Exploit Guard"
New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\Defender\Windows Defender Exploit Guard" -Name "ASR"
New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\Defender\Windows Defender Exploit Guard" -Name "Network Protection"

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy" -Name "{35378EAC-683F-11D2-A89A-00C04FBBCFA2}"
Write-Host "Setting Registry values"
Write-Host "---------------------------------------------------------------------"
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog" -Name "Setup"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup" -Name "MaxSize" -Value: 32768


Write-Host "Status of the 'Turn on PowerShell Script Block Logging' setting"
Write-Host "---------------------------------------------------------------------"
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell" -Name "ScriptBlockLogging"
New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell" -Name "Transcription"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
Write-Host "---------------------------------------------------------------------"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value: 0


Write-Host "Status of the 'Windows Firewall: Log Successful Connections (Private)' setting"
Write-Host "Status of the 'Windows Firewall: Firewall state (Public)' setting
            Status of the 'Windows Firewall: Inbound connections (Public)' setting
            Status of the 'Windows Firewall: Outbound connections (Public)' setting
            Status of the 'Windows Firewall: Display a notification (Public)' setting"
Write-Host "---------------------------------------------------------------------"
Write-Host "---------------------------------------------------------------------"
New-Item -Path "HKLM:\Software\Policies\Microsoft" -Name "WindowsFirewall"
Write-Host "---------------------------------------------------------------------"
New-Item -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall" -Name "PrivateProfile"
Write-Host "---------------------------------------------------------------------"
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall" -Name "DomainProfile"
Write-Host "---------------------------------------------------------------------"
New-Item -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile" -Name "Logging"
Write-Host "---------------------------------------------------------------------"
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall" -Name PublicProfile
Write-Host "---------------------------------------------------------------------"
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" -Name "Logging"
Write-Host "---------------------------------------------------------------------"
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" -Name "Logging"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
Write-Host "---------------------------------------------------------------------"
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" -Name "LogSuccessfulConnections" -Value: 1
Write-Host "---------------------------------------------------------------------"

Write-Host "Setting Registry values"
Write-Host "---------------------------------------------------------------------"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" -Name EnableFirewall -Value 1
Write-Host "---------------------------------------------------------------------"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" -Name DefaultInboundAction -Value 1
Write-Host "---------------------------------------------------------------------"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" -Name DefaultOutboundAction -Value 0
Write-Host "---------------------------------------------------------------------"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" -Name DisableNotifications -Value 1

Write-Host "Status of the 'default behavior for AutoRun'"
Write-Host "---------------------------------------------------------------------"
Get-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
Write-Host "---------------------------------------------------------------------"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutorun" -Value: 1


Write-Host "Status of the 'Reset Account Lockout Counter After' setting
            Status of the 'Account Lockout Duration' setting (invalid login attempts)
            Status of the 'Account Lockout Threshold' setting (invalid login attempts)
            Status of the 'Enforce password history' setting
            Status of the 'Minimum Password Age' setting"
Write-Host "Setting Registry values"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"

net accounts /lockoutwindow:1
net accounts /lockoutwindow:15
net accounts /lockoutthreshold:1
net accounts /lockoutthreshold:10
net accounts /lockoutduration:30
net accounts /lockoutduration:15
net accounts /UNIQUEPW:4
net accounts /UNIQUEPW:24
net accounts /MINPWAGE:1



Write-Host "Status of the 'Allow Microsoft accounts to be optional' setting"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "MSAOptional" -Value: 1


Write-Host "Status of the 'Interactive Logon: Do Not Display Last User Name' setting"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DontDisplayLastUserName" -Value: 1


Write-Host "Status of 'logon banner title' setting (Legal Notice)"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LegalNoticeCaption" -Value: "STATUTORY WARNING"


Write-Host "Status of the 'Enable insecure guest logons' setting"
Write-Host "Setting Registry values"
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\LanmanWorkstation" -Name "AllowInsecureGuestAuth" -Value 0


Write-Host "Status of the 'Turn off downloading of print drivers over HTTP' setting"
Write-Host "---------------------------------------------------------------------"
New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows NT" -Name "Printers"
Write-Host "Setting Registry values"
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers" -Name "DisableWebPnPDownload" -Value 1



Write-Host "Status of 'Manage preview builds: Set the behavior of receiving preview builds' setting)"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" -Name "ManagePreviewBuildsPolicyValue" -Value 0


Write-Host "Status of 'Manage preview builds' group policy"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" -Name "ManagePreviewBuilds" -Value 0


Write-Host "Status of the 'Select when Feature Updates are received - DeferFeatureUpdates' setting"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferFeatureUpdates" -Value 1


Write-Host "Status of the 'Select when Quality Updates are received' 'DeferQualityUpdates' setting"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferQualityUpdates" -Value 1

Write-Host "Status of the 'Configure Automatic Updates Option: Scheduled install day' policy setting"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "ScheduledInstallDay" -Value 0


Write-Host "Status of the 'Minimum Password Length' setting'"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
net accounts /MINPWLEN:14



Write-Host "Status of the 'User Account Control: Behavior of the elevation prompt for standard users' setting"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorUser" -Value 0


Write-Host "Status of the 'User Account Control: Behavior of the elevation prompt for standard users' setting"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ForceUnlockLogon" -Value 1


Write-Host "Status of 'Attack Surface Reduction' group policy"
Write-Host "Status of 'Prevent users and apps from accessing dangerous websites' setting"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"

Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Defender\Windows Defender Exploit Guard\ASR" -Name "ExploitGuard_ASR_Rules" -Value 1
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Defender\Windows Defender Exploit Guard\Network Protection" -Name "EnableNetworkProtection" -Value 1


Write-Host "Status of the 'Network Security: Minimum session security for NTLM SSP based (including secure RPC) clients' setting"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "ntlmminclientsec" -Value: 536870912


Write-Host "Status of the 'Windows Firewall: Firewall state (Domain)' setting"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" -Name "EnableFirewall" -Value 1


Write-Host "Status of the 'Turn off Data Execution Prevention for Explorer' setting"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"

Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Explorer" -Name "NoDataExecutionPrevention" -Value 0


Write-Host "Status of the 'Network Security: LAN Manager Authentication Level' setting"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Value 5


Write-Host "Status of the 'Require domain users to elevate when setting a network's location'setting"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Network Connections" -Name "NC_StdDomainUserSetLocation" -Value 1


Write-Host "Status of the 'Disallow Digest authentication' setting (WinRM client)"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client" -Name "AllowDigest" -Value 0


Write-Host "Status of the 'Interactive Logon: Smart Card Removal Behavior' setting"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "ScRemoveOption" -Value 0


Write-Host "Status of the 'Interactive Logon: Require Domain Controller authentication to unlock workstation' setting"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "ForceUnlockLogon" -Value 0


Write-Host "Status of the 'Lock screen slide show' setting"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreenSlideshow" -Value 1


Write-Host "Status of the 'Windows Firewall: Inbound connections (Private)' setting"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile" -Name "DefaultInboundAction" -Value: 1


Write-Host "Status of the 'Windows Firewall: Firewall state (Private)' setting"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile" -Name "EnableFirewall" -Value: 1



Write-Host "Status of the 'Prevent users from modifying settings' setting for Windows Defender Exploit Protection"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft" -Name "Windows Defender Security Center"
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center" -Name "App and Browser protection"
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender Security Center\App and Browser protection" -Name "DisallowExploitProtectionOverride" -Value: 1


Write-Host "Status of the 'Block all consumer Microsoft account user authentication' (DisableUserAuth) Group Policy setting"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft" -Name "MicrosoftAccount"
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\MicrosoftAccount" -Name "DisableUserAuth" -Value: 1


Write-Host "Status of the 'Notify antivirus programs when opening attachments' configuration [For Windows user]"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies" -Name "Attachments"
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "ScanWithAntiVirus" -Value: 3


Write-Host "Status of the 'Security: Maximum log size' setting (in KB)'"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog" -Name "Security"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" -Name "MaxSize" -Value: 196608


Write-Host "Status of the Security Options 'Interactive logon: Machine inactivity limit' setting (seconds)"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "InactivityTimeoutSecs" -Value 900


Write-Host "Status of the 'Select when Feature Updates are received - BranchReadinessLevel' setting"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "BranchReadinessLevel" -Value 20


Write-Host "Status of the 'Do not display network selection UI' setting"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DontDisplayNetworkSelectionUI" -Value: 1


Write-Host "Status of the 'Windows Firewall: Display a notification (Domain)' setting"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" -Name "DisableNotifications" -Value: 1


Write-Host "Status of the 'Use enhanced anti-spoofing when available' setting"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft" -Name "Biometrics"
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics" -Name "FacialFeatures"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures" -Name "EnhancedAntiSpoofing" -Value: 1


Write-Host "Status of the 'System: Maximum log size' setting (in KB)'"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog" -Name "System"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System" -Name "MaxSize" -Value: 32768


Write-Host "Status of the 'Windows Firewall: Display a notification (Private)' setting"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile" -Name "DisableNotifications" -Value: 1


Write-Host "Status of the 'Windows Firewall: Display a notification (Private)' setting"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile" -Name "DisableNotifications" -Value: 1


Write-Host "Status of the 'Remote host allows delegation of non-exportable credentials' (AllowProtectedCreds) setting"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" -Name "AllowProtectedCreds" -Value: 1


Write-Host "Status of the 'Network security: Allow PKU2U authentication requests to this computer to use online identities' setting"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
New-Item -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "pku2u"
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa\pku2u" -Name "AllowOnlineID" -Value: 0

Write-Host "Status of the 'Do not allow passwords to be saved' setting (Terminal Services)"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "DisablePasswordSaving" -Value: 1


Write-Host "Status of the 'Devices: Allowed to format and eject removable media' setting (NTFS formatted devices)"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AllocateDASD" -Value: 0



Write-Host "Status of the 'Microsoft network server: Digitally Sign Communications (if Client agrees) setting"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "EnableSecuritySignature" -Value: 0


Write-Host "Status of the 'Turn on PowerShell Transcription' setting"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -Value: 0


Write-Host "Status of the 'Windows Firewall: Inbound connections (Domain)' setting"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" -Name "DefaultInboundAction" -Value 1


Write-Host "Status of "Password protect the screen saver" setting for Windows users"
Write-Host "Status of 'Enable screen saver' configuration for Windows users"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows" -Name "Control Panel"
New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Control Panel" -Name "Desktop"
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop" -Name "ScreenSaverIsSecure" -Value 1
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop" -Name "ScreenSaveActive" -Value 1


Write-Host "Status of the 'Select when Quality Updates are received' 'DeferQualityUpdatesPeriodInDays' Setting"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferQualityUpdatesPeriodInDays" -Value 0


Write-Host "Status of the 'Always install with elevated privileges' setting for Windows User"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows" -Name "Installer"
Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -Value 0


Write-Host "Status of the 'Disallow Autoplay for non-volume devices' setting"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoAutoplayfornonVolume" -Value 1


Write-Host "Status of the 'Always prompt for password upon connection' setting (Terminal Services)"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fPromptForPassword" -Value 1


Write-Host "Status of 'Block Office applications from injecting code into other processes' ASR rule (75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84)"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft" -Name "Windows Defender"
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "Windows Defender Exploit Guard"
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard" -Name "ASR"
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR" -Name "Rules"
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" -Name "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84" -Value 1


Write-Host "Status of the 'Turn off Microsoft consumer experiences' setting"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Value 1


Write-Host "Status of the 'Turn off Internet download for Web publishing and online ordering wizards' setting"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoWebServices" -Value 1


Write-Host "Status of the Security Options 'Accounts: Block Microsoft accounts' setting"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "NoConnectedUser" -Value 3


Write-Host "Status of the 'Application: Maximum log size' setting (in KB)"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog" -Name "Application"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application" -Name "MaxSize" -Value 32768


Write-Host "Status of the 'Lock screen camera' setting"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreenCamera" -Value 1


Write-Host "Status of the 'Windows Firewall: Log dropped packets (Domain)' setting"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" -Name "LogDroppedPackets" -Value 1


Write-Host "Status of the 'Windows Firewall: Outbound connections (Private)' setting"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" -Name "DefaultOutboundAction" -Value 0

Write-Host "Status of the 'Solicited Remote Assistance' policy setting (Terminal Services)"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fAllowToGetHelp" -Value 0


Write-Host "Status of the 'Microsoft network server: Server SPN target name validation level' setting"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMBServerNameHardeningLevel" -Value 0


Write-Host "Status of the 'Require use of specific security layer for remote (RDP) connections' setting"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "SecurityLayer" -Value 2


Write-Host "Status of the 'Do not use temporary folders per session' Group Policy setting"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "PerSessionTempDir" -Value 1


Write-Host "Status of 'Windows Defender - Turn on e-mail scanning' setting"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "Scan"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" -Name "DisableEmailScanning" -Value 0


Write-Host "Status of the 'Do not suggest third-party content in Windows spotlight' setting"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableThirdPartySuggestions" -Value 1


Write-Host "Status of 'Scan removable drives (Windows Defender)' setting"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Scan" -Name "DisableRemovableDriveScanning" -Value 0


Write-Host "Status of the contents of the 'login banner' (Windows/Unix/Linux)"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LegalNoticeText" -Value "This computer system (including all hardware software, related equipment networks and network devices) is the property of Virtusa
Corporation, including its direct and indirect subsidiaries, and is provided for authorized business purpose only. All actions performed using
this asset may be monitored for all lawful purpose including ensuring, authorized use for management of the system to facilitate protection
against unauthorized access, prevent data leakage and to verify security procedures and operational procedures. The monitoring on this
system shall include audits by Company authorized personnel or its representatives to test or verify the validity, security and survivability of
this system. During monitoring, information may be examined, recorded, copied and used for, authorized purposes. All information placed on
or sent to this system may be subject to such monitoring procedures without any prior notice or intimation to you. Use of this computer system
constitutes consent to such monitoring. I will refrain from circumventing any security measure, control or system which has been implemented
to restrict access to secure area, computers, networks, systems or information. Any unauthorized access use or modification of the computer
system can result in disciplinary action including termination or possible civil or criminal penalties."


Write-Host "Status of the 'Configure Windows Defender SmartScreen' setting"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Value "1"


Write-Host "Status of the 'Allow Windows Ink Workspace' setting"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableThirdPartySuggestions" -Value "1"


Write-Host "Status of the 'Allow Windows Ink Workspace' setting"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft" -Name "WindowsInkWorkspace"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Name "AllowWindowsInkWorkspace" -Value "1"


Write-Host "Status of the "Do not preserve zone information in file attachments" setting for Windows users"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "SaveZoneInformation" -Value "2"


Write-Host "Status of the 'Configure Windows Defender SmartScreen - Pick one of the following' setting"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "ShellSmartScreenLevel" -Value "Block"


Write-Host "Status of 'logon banner title' setting (Legal Notice)"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "LegalNoticeCaption" -Value "STATUTORY WARNING"


Write-Host "Status of the 'Block user from showing account details on sign-in' setting"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "BlockUserFromShowingAccountDetailsOnSignin" -Value "1"


Write-Host "Status of the 'Require user authentication for remote connections by using Network Level Authentication' setting"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "UserAuthentication" -Value "1"


Write-Host "Status of the 'Prevent users from sharing files within their profile' setting"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies" -Name "Explorer"
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoInplaceSharing" -Value "1"

Write-Host "Status of the 'Do not delete temp folder upon exit' setting"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "DeleteTempDirsOnExit" -Value "1"


Write-Host "Status of the 'Boot-Start Driver Initialization Policy' setting"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
New-Item -Path "HKLM:\System\CurrentControlSet\Policies" -Name "EarlyLaunch"
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Policies\EarlyLaunch" -Name "DriverLoadPolicy" -Value "3"


Write-Host "Status of the 'Set Client Connection Encryption Level' setting (Terminal Services)"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "MinEncryptionLevel" -Value "3"


Write-Host "Configure 'Network Security:Configure encryption types allowed for Kerberos'"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "Kerberos"
New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos" -Name "Parameters"
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" -Name "SupportedEncryptionTypes" -Value "2147483640"


Write-Host "Status of the 'Include command line in process creation events' setting"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -Value "0"


Write-Host "Status of the 'Always install with elevated privileges' setting for Windows User"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
New-Item -Path "HKCU:\Software\Policies\Microsoft\Windows\CurrentVersion" -Name "PushNotifications"
Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "NoToastApplicationNotificationOnLockScreen" -Value 1


Write-Host "Status of 'Toggle user control over Insider builds'"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Name "AllowBuildPreview" -Value "0"


Write-Host "Status of the 'Allow Telemetry' setting"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value "1"


Write-Host "Status of the 'Windows Firewall: Log dropped packets (Private)' setting"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" -Name "LogDroppedPackets" -Value: 1


Write-Host "Status of the 'Registry policy processing (Option: Do not apply during periodic background processing)' setting"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\" -Name "NoBackgroundPolicy" -Value "0"


Write-Host "Status of the 'Do not enumerate connected users on domain-joined computers' setting"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DontEnumerateConnectedUsers" -Value: 1


Write-Host "Status of the 'Turn off heap termination on corruption' setting"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Explorer" -Name "NoHeapTerminationOnCorruption" -Value 0


Write-Host "Status of the 'Encryption Oracle Remediation' group policy"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "CredSSP"
New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP" -Name "Parameters"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters" -Name "AllowEncryptionOracle" -Value 0


Write-Host "Status of the Configure 'Turn off app notifications on the lock screen'"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "DisableLockScreenAppNotifications" -Value 1


Write-Host "Status of the 'Force specific screen saver:Screen saver executable name' Setting [Windows users]"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop" -Name "SCRNSAVE.EXE" -Value "scrnsave.scr"


Write-Host "Status of "Do not display the password reveal button""
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CredUI" -Name "DisablePasswordReveal" -Value 1
