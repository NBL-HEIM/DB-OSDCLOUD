<#PSScriptInfo
.VERSION 23.6.10.1
.GUID 9670c013-d1b1-4f5d-9bd0-0fa185b9f203
.AUTHOR David Segura @SeguraOSD
.COMPANYNAME osdcloud.com
.COPYRIGHT (c) 2023 David Segura osdcloud.com. All rights reserved.
.TAGS OSDeploy OSDCloud WinPE OOBE Windows AutoPilot
.LICENSEURI 
.PROJECTURI https://github.com/OSDeploy/OSD
.ICONURI 
.EXTERNALMODULEDEPENDENCIES 
.REQUIREDSCRIPTS 
.EXTERNALSCRIPTDEPENDENCIES 
.RELEASENOTES
Script should be executed in a Command Prompt using the following command
powershell Invoke-Expression -Command (Invoke-RestMethod -Uri sandbox.osdcloud.com)
This is abbreviated as
powershell iex (irm sandbox.osdcloud.com)
#>
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    PowerShell Script which supports the OSDCloud environment
.DESCRIPTION
    PowerShell Script which supports the OSDCloud environment
.NOTES
    Version 23.6.10.1
.LINK
    https://raw.githubusercontent.com/OSDeploy/OSD/master/cloud/sandbox.osdcloud.com.ps1
.EXAMPLE
    powershell iex (irm sandbox.osdcloud.com)
#>
[CmdletBinding()]
param()
$ScriptName = 'sandbox.osdcloud.com'
$ScriptVersion = '23.6.10.1'

#region Initialize
$Transcript = "$((Get-Date).ToString('yyyy-MM-dd-HHmmss'))-$ScriptName.log"
$null = Start-Transcript -Path (Join-Path "$env:SystemRoot\Temp" $Transcript) -ErrorAction Ignore

if ($env:SystemDrive -eq 'X:') {
    $WindowsPhase = 'WinPE'
}
else {
    $ImageState = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\State' -ErrorAction Ignore).ImageState
    if ($env:UserName -eq 'defaultuser0') {$WindowsPhase = 'OOBE'}
    elseif ($ImageState -eq 'IMAGE_STATE_SPECIALIZE_RESEAL_TO_OOBE') {$WindowsPhase = 'Specialize'}
    elseif ($ImageState -eq 'IMAGE_STATE_SPECIALIZE_RESEAL_TO_AUDIT') {$WindowsPhase = 'AuditMode'}
    else {$WindowsPhase = 'Windows'}
}

Write-Host -ForegroundColor Green "[+] $ScriptName $ScriptVersion ($WindowsPhase Phase)"
Invoke-Expression -Command (Invoke-RestMethod -Uri functions.osdcloud.com)
#endregion

#region Admin Elevation
$whoiam = [system.security.principal.windowsidentity]::getcurrent().name
$isElevated = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if ($isElevated) {
    Write-Host -ForegroundColor Green "[+] Running as $whoiam (Admin Elevated)"
}
else {
    Write-Host -ForegroundColor Red "[!] Running as $whoiam (NOT Admin Elevated)"
    Break
}
#endregion

#region Transport Layer Security (TLS) 1.2
Write-Host -ForegroundColor Green "[+] Transport Layer Security (TLS) 1.2"
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
#endregion

#region WinPE
if ($WindowsPhase -eq 'WinPE') {
    #Process OSDCloud startup and load Azure KeyVault dependencies
    osdcloud-StartWinPE -OSDCloud -KeyVault
    Write-Host -ForegroundColor Cyan "To start a new PowerShell session, type 'start powershell' and press enter"
    Write-Host -ForegroundColor Cyan "Start-OSDCloud, Start-OSDCloudGUI, or Start-OSDCloudAzure, can be run in the new PowerShell window"
    
    #Stop the startup Transcript.  OSDCloud will create its own
    $null = Stop-Transcript -ErrorAction Ignore
}
#endregion

#region Specialize
if ($WindowsPhase -eq 'Specialize') {
    $null = Stop-Transcript -ErrorAction Ignore
}
#endregion

#region AuditMode
if ($WindowsPhase -eq 'AuditMode') {
    $null = Stop-Transcript -ErrorAction Ignore
}
#endregion

#region OOBE
if ($WindowsPhase -eq 'OOBE') {
       
    #Load everything needed to run AutoPilot and Azure KeyVault
    OSDCloud-StartOOBE -Language -DateTime -Autopilot
    
Connect-MgGraph

Write-Host "==================AutoPilot Tag Selection=================="
$Tag = 0
Write-Host "Press '1' for AMER"
Write-Host "Press '2' for EMEA Region"
Write-Host "Press '3' for EMEA Region with COLO"
Write-Host "Press '4' for APAC"
Write-Host "Press '5' for AMER-TST"

$input = Read-Host "Please select the region"
switch ($input)
{
    '1'{
        $Tag = "AMER"
    }
    '2'{
        $Tag = "EMEA"
    }
    '3'{
        $Tag = "EMEA-COLO"
    }
    '4'{
        $Tag = "APAC"
    }
    '5'{
        $Tag = "AMER-TST"
    }

}
    $serial = (get-wmiobject -class win32_bios).SerialNumber
    $Device = get-autopilotdevice -serial $serial
    if($Device -eq $null)
        { 
            Write-Host "Device is not registered in the Intune Autopilot Device list - Enrolling...."
            Start-Sleep -Seconds 10
            $AutoPilotRegisterCommand = "Get-WindowsAutoPilotInfo -Online -GroupTag $Tag -Assign"
            OSDCloud-AutoPilotRegisterCommand -Command $AutoPilotRegisterCommand;Start-Sleep -Seconds 30
        }
    Else
        {
            Write-Host "Device is already registered in the Intune Autopilot Device list"
            Write-Host "Updating device with new tag value.  Please wait 5 minutes... "
            $id = (get-autopilotdevice -serial $serial).id
            Set-autopilotdevice -id $id -groupTag $Tag
            Start-Sleep -Seconds 300
        }

Write-Host "===AutoPilot Device Registration Completed==="
Start-Sleep -Seconds 5
Write-Host "Please verify the enrolled device is in the Intune Autopilot Device list before continuing"
Write-Host "Serial = $Serial"
Write-Host "Autopilot Assiged Tag = $Tag"
Write-Host "Pending Computer Name = $Tag$Serial"
Start-Sleep -Seconds 10

    $null = Stop-Transcript -ErrorAction Ignore
}
#endregion

#region Windows
if ($WindowsPhase -eq 'Windows') {
    #Load OSD and Azure stuff
    $null = Stop-Transcript -ErrorAction Ignore
}
#endregion

$env:Path += ';C:\Program Files\WindowsPowerShell\Scripts'
install-script get-WindowsAutopilotInfo