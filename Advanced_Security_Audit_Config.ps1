<#
    .SYNOPSIS
        Installation script for Advanced Security Auditing and Forensic Logging Configuration

    .DESCRIPTION
        This PowerShell script configures advanced security auditing and forensic logging for Windows systems, whether they are workstations, domain controllers, or servers. It adjusts audit policies based on the system type, ensuring thorough logging of user activities, system events, and security incidents. This approach helps ensure that critical logs are captured, providing enhanced visibility for monitoring and forensic analysis. 

        Designed for use on these operating systems:

        Windows Server 2022
        Windows Server 2019
        Windows Server 2016
        Windows Server 2012
        Windows Server 2012 R2
        Windows Server 2008
        Windows 11
        Windows 10
        Windows 8.1
        Windows 7

        To execute this script:
          1) Open PowerShell window as administrator
          2) Allow script execution by running command "Set-ExecutionPolicy Bypass -Scope Process -Force"
          3) Execute the script by running ".\Advanced_Security_Audit_Config.ps1"

    .NOTES
        Version:        1.0
        Author:         H0wl3r
        CreationDate:   08-09-2024

    .EXAMPLE
        .\Advanced_Security_Audit_Config.ps1

    .LINK
        https://github.com/H0wl3r/Advanced-Security-Audit-Configuration
#>

# Check script is running as administrator
Write-Host ""
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-Not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "Please run this script as administrator" -ForegroundColor Red
        Write-Host ""
        Read-Host "      Press Enter to exit ..."
        exit 1
    }

Write-Host "Advanced Security Auditing and Forensic Logging Configuration" -ForegroundColor Cyan
Write-Host ""
Start-Sleep -seconds 3

########################################
#####     Log Retention Policy     #####
########################################

Write-Host "Log Retention Policy Configuration ..." -ForegroundColor Cyan
Write-Host ""
Start-Sleep -seconds 3

$LogNames = @(
    "Application",
    "Security",
    "System",
    "Microsoft-Windows-AppLocker/EXE and DLL",
    "Microsoft-Windows-AppLocker/MSI and Script",
    "Microsoft-Windows-AppLocker/Packaged app-Deployment",
    "Microsoft-Windows-AppLocker/Packaged app-Execution",
    "Microsoft-Windows-Bits-Client/Operational",
    "Microsoft-Windows-CodeIntegrity/Operational",
    "Microsoft-Windows-Diagnosis-Scripted/Operational",
    "Microsoft-Windows-DriverFrameworks-UserMode/Operational",
    "Microsoft-Windows-Kernel-Boot/Operational",
    "Microsoft-Windows-NTLM/Operational",
    "Microsoft-Windows-PowerShell/Operational",
    "Microsoft-Windows-PrintService/Admin",
    "Microsoft-Windows-PrintService/Operational",
    "Microsoft-Windows-Security-Mitigations/KernelMode",
    "Microsoft-Windows-Security-Mitigations/UserMode",
    "Microsoft-Windows-SmbClient/Security",
    "Microsoft-Windows-TaskScheduler/Operational",
    "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
    "Microsoft-Windows-Windows Defender/Operational",
    "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
    "Microsoft-Windows-WMI-Activity/Operational"
)

[int]$LargeSize = 1073741824  # 1GB in binary
[int]$SmallSize = 134217728   # 128MB in binary

foreach ($log in $LogNames) {
    try {
        if ($log -eq "Security" -or $log -eq "Microsoft-Windows-PowerShell/Operational") { 
            Write-Host "Configuring " -NoNewline; Write-Host "$log" -ForegroundColor Cyan -NoNewline; Write-Host " to " -NoNewline; Write-Host "1GB" -ForegroundColor Yellow -NoNewline; Write-Host "."
            wevtutil sl $log /ms:$LargeSize
        } else {
            Write-Host "Configuring " -NoNewline; Write-Host "$log" -ForegroundColor Cyan -NoNewline; Write-Host " to " -NoNewline; Write-Host "128MB" -ForegroundColor Yellow -NoNewline; Write-Host "."
            wevtutil sl $log /ms:$SmallSize
            
        }
    } catch {
        Write-Host "Error: The log '$log' could not be found on this system." -ForegroundColor Red
    }
}

############################################################
#####     Audit Log Status Check and Configuration     #####
############################################################

Write-Host ""
Write-Host "Audit Log Status Check and Configuration ..." -ForegroundColor Cyan
Write-Host ""
Start-Sleep -seconds 3

# Enable Logging
foreach ($log in $LogNames) {
    try {
        $logStatus = wevtutil gl $log | Select-String "enabled"
        if ($logStatus -like "*enabled: false*") {
            wevtutil sl $log /e:true
            Write-Host "Enabled Audit Log " -NoNewline; Write-Host "$log" -ForegroundColor Cyan -NoNewline; Write-Host "."
        } elseif ($logStatus -like "*enabled: true*") {
            Write-Host "Enabled Audit Log " -NoNewline; Write-Host "$log" -ForegroundColor Cyan -NoNewline; Write-Host "."
        } else {
            Write-Host "Could not determine the status of $log." -ForegroundColor Red
        }
    } catch {
        Write-Host "An error occurred while processing $log" -ForegroundColor Red
    }
}

#################################################################################
#####     Advanced Security Auditing and Forensic Logging Configuration     #####
#################################################################################

Write-Host ""
Write-Host "Advanced Security Auditing and Forensic Logging Configuration ..." -ForegroundColor Cyan
Write-Host ""
Start-Sleep -seconds 3

# Function to check OS
function Get-SystemType {
    $osType = (Get-CimInstance -ClassName Win32_OperatingSystem).ProductType
    return $osType
}

# Function to apply Audit Policies
function Apply-AuditPolicies {
    param (
        [array]$policies
    )
    foreach ($policy in $policies) {
        try {
            auditpol /set /subcategory:$policy /success:enable /failure:enable > $null
            Write-Host "Applied Audit Policy " -NoNewline; Write-Host "$policy" -ForegroundColor Cyan 
        } catch {
            Write-Host "Failed to apply Audit Policy $policy. Error: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

$AuditPolicy_1 = @(
    "Account Lockout",
    "Audit Policy Change",
    "Authentication Policy Change",
    "Computer Account Management",
    "Credential Validation",
    "DPAPI Activity",
    "Detailed File Share",
    "File Share",
    "Filtering Platform Connection",
    "Handle Manipulation",
    "IPsec Driver",
    "Logoff",
    "Logon",
    "MPSSVC Rule-Level Policy Change",
    "Other Account Management Events",
    "Other Logon/Logoff Events",
    "Other Object Access Events",
    "Other Policy Change Events",
    "Plug and Play Events",
    "Process Creation",
    "RPC Events",
    "Removable Storage",
    "SAM",
    "Security Group Management",
    "Security State Change",
    "Security System Extension",
    "Special Logon",
    "System Integrity",
    "User Account Management"
)

$AuditPolicy_2 = @(
    "Directory Service Access",
    "Directory Service Changes"
)

$AuditPolicy_3 = @(
    "Certification Services",
    "Kerberos Authentication Service",
    "Kerberos Service Ticket Operation"
)

# Enable Audit Policies 
$osType = Get-SystemType
if ($osType -eq 1) {
    Write-Host "Applying policies to Workstation: " -NoNewline; Write-Host "$env:computername" -ForegroundColor Yellow
    Write-Host ""
    Apply-AuditPolicies -policies $AuditPolicy_1
}
elseif ($osType -eq 2) {
    Write-Host "Applying policies to Domain Controller: "-NoNewline; Write-Host "$env:computername" -ForegroundColor Yellow
    Write-Host ""
    Apply-AuditPolicies -policies $AuditPolicy_1
    Apply-AuditPolicies -policies $AuditPolicy_2
    Apply-AuditPolicies -policies $AuditPolicy_3
}
elseif ($osType -eq 2) {
    Write-Host "Applying policies to Server: "-NoNewline; Write-Host "$env:computername" -ForegroundColor Yellow
    Write-Host ""
    Apply-AuditPolicies -policies $AuditPolicy_1
    Apply-AuditPolicies -policies $AuditPolicy_3
}
else {
    Write-Host "Error: Unrecognized system type: $osType" -ForegroundColor Red
    throw "Invalid system type: $osType. Expected values: 1 (Workstation), 2 (Domain Controller), or 3 (Server)."
}

# Enable Comand Line Auditing
try {
    reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit /v ProcessCreationIncludeCmdLine_Enabled /f /t REG_DWORD /d 1 > $null
    Write-Host "Enabled " -NoNewline; Write-Host "Command Line Auditing" -ForegroundColor Cyan
} catch {
    Write-Host "Failed to enable Command Line Auditing. Error: $($_.Exception.Message)" -ForegroundColor Red
}

# Enable PowerShell Script Block Logging
try {
    reg add HKLM\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging /v EnableScriptBlockLogging /f /t REG_DWORD /d 1 > $null
    Write-Host "Enabled " -NoNewline; Write-Host "PowerShell ScriptBlock Logging" -ForegroundColor Cyan
} catch {
    Write-Host "Failed to enable PowerShell ScriptBlock Logging. Error: $($_.Exception.Message)" -ForegroundColor Red
}

# Enable Module logging
try {
    reg add HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging /v EnableModuleLogging /f /t REG_DWORD /d 1 > $null
reg add HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames  /f /v ^* /t REG_SZ /d ^* > $null
    Write-Host "Enabled " -NoNewline; Write-Host "PowerShell Module Logging" -ForegroundColor Cyan
} catch {
    Write-Host "Failed to enable PowerShell Module Logging. Error: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host ""

gpupdate.exe /Force

Write-Host ""
Write-Host "Configuration Enabled" -ForegroundColor Green -NoNewline; Write-Host " on " -NoNewline; Write-Host "$env:computername" -ForegroundColor Yellow
Write-Host ""

# Message Box
Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.MessageBox]::Show("Advanced Security Auditing and Forensic Logging Configuration Enabled.", "Completion", 'OK', 'Information')
exit 0