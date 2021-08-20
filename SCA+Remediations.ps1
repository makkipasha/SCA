####### SCA Remediations for ImageBuilder #######
####### Script Started ######
 
Write-Host "Status of the Setup: Maximum Log Size (KB) setting"
Write-Host "---------------------------------------------------------------------"
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows" -Name "EventLog"
Write-Host "---------------------------------------------------------------------"
Write-Host "Setting Registry values"
Write-Host "---------------------------------------------------------------------"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog" -Name "EventLog" -Value: MaxSize
