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
    OSDCloud-StartOOBE -Display -Language -DateTime -Autopilot
    
Connect-MgGraph

Write-Host "==================AutoPilot Tag Selection=================="
$Tag = 0
Write-Host "1: Press '1' for United States"
Write-Host "2: Press '2' for Great Britain"
Write-Host "3: Press '3' for France"
Write-Host "4: Press '4' for Germany"
Write-Host "5: Press '5' for Canada"
Write-Host "6: Press '6' for Denmark"
Write-Host "7: Press '7' for Ireland"
Write-Host "8: Press '8' for Norway"
Write-Host "9: Press '9' for Portugal"
Write-Host "10: Press '10' for Spain"
Write-Host "11: Press '11' for Sweden"
Write-Host "12: Press '12' for Turkey"
Write-Host "13: Press '13' for Australia"

$input = Read-Host "Please select the region"
switch ($input)
{
    '1'{
        $Tag = "US"
    }
    '2'{
        $Tag = "GB"
    }
    '3'{
        $Tag = "FR"
    }
    '4'{
        $Tag = "DE"
    }
    '5'{
        $Tag = "CA"
    }
    '6'{
        $Tag = "DK"
    }
    '7'{
        $Tag = "IE"
    }
    '8'{
        $Tag = "NO"
    }
    '9'{
        $Tag = "PT"
    }
    '10'{
        $Tag = "ES"
    }
    '11'{
        $Tag = "SE"
    }
    '12'{
        $Tag = "TR"
    }
    '13'{
        $Tag = "AU"
    }
}

    $Device = get-autopilotdevice -serial $serial
    if($Device -eq $null)
        { 
            $AutoPilotRegisterCommand = "Get-WindowsAutoPilotInfo -Online -GroupTag $Tag -Assign"
            OSDCloud-AutoPilotRegisterCommand -Command $AutoPilotRegisterCommand;Start-Sleep -Seconds 30
        }
    Else
        {
            $serial = (get-wmiobject -class win32_bios).SerialNumber
            $id = (get-autopilotdevice -serial $serial).id
            Set-autopilotdevice -id $id -groupTag $Tag
        }

Write-Host "===AutoPilot Tag Selection Completed==="
Write-Host "Please go to https://intune.microsoft.com/#view/Microsoft_Intune_Enrollment/AutopilotDevices.ReactView/filterOnManualRemediationRequired~/false to check Assigned profile status"

    $null = Stop-Transcript -ErrorAction Ignore
}
#endregion

#region Windows
if ($WindowsPhase -eq 'Windows') {
    #Load OSD and Azure stuff
    $null = Stop-Transcript -ErrorAction Ignore
}
#endregion


install-script get-WindowsAutopilotInfo