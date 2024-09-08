# Advanced Security Auditing and Forensic Logging Configuration

# Contents

- [About](#About)
- [Why](#Why)
- [Scope](#Scope)
- [Advanced Security Auditing and Forensic Logging Configuration](#Advanced-Security-Auditing-an-Forensi-Logging-Configuration)
	- [Strengths](#Strengths)
	- [Outcome](#Outcome)
- [Execution](#Execution)
	- [Local](#Local)
	- [Remote](#Remote)
- [Compatibility](#Compatibility) 
- [Audit Logs](#audit-logs)
- [Audit Policies](#audit-polices)
- [References](#References)

# About

This PowerShell script configures advanced security auditing and forensic logging for Windows systems, whether they are workstations, domain controllers, or servers. It adjusts audit policies based on the system type, ensuring thorough logging of user activities, system events, and security incidents. This approach helps ensure that critical logs are captured, providing enhanced visibility for monitoring and forensic analysis.
# Why

Default Windows logs fall short in providing the visibility needed for real security monitoring. Critical events like process creation, PowerShell execution, and file or registry changes are either not logged or lack enough detail to catch malicious activity. The logs are noisy, filled with irrelevant data that buries important signals. On top of that EVTX logs have short retention times with the potential for evidence to be lost. Without serious tweaking, default logs just don’t cut it for detecting modern threats or responding effectively.
# Scope

In a remote, resource-constrained environment where software installation (such as EDR & Sysmon) and real-time log forwarding are not feasible, deploying an advanced security-focused audit policy enables extensive threat detection while offering robust forensic capabilities. This approach is essential for legacy systems or environments with limited connectivity and hardware constraints.
# Advanced Security Auditing and Forensic Logging Configuration
### *Strengths:*

- **Comprehensive Event Logging**: Provides detailed logs on user activity, file access, and system configuration changes, which can be analysed post-incident for forensic investigation.
- **Monitors Critical Processes:** Logs unauthorised processes, script execution and suspicious network connections.
- **Incident Reconstruction**: Facilitates the ability to trace the attacker's actions, identify methods used, and assess the full scope of the breach.
- **Tamper Detection**: Tracks any modifications to the audit policy itself, ensuring that attempts to disable or bypass logging mechanisms are detected.
- **Evidence Retention**: The policy increases log storage capacity to prevent overwriting, ensuring critical logs are retained locally and can be retrieved for forensic analysis, preserving essential evidence for investigations.
- **No Installation Overhead:** Uses native logging tools, avoiding software installation and performance impacts.
### *Outcome:*

- **Broad Threat Detection:** The policy covers most threats without response capabilities.
- **Forensic Logging:** Logs are stored locally and can be forwarded to a SIEM for analysis when connectivity allows.
- **Compliance:** Meets security and compliance requirements despite technological limitations.

# Execution

### Local

Follow the steps below to execute the script on a local environment.

1. Open a PowerShell window as administrator.
2. Allow script execution by running command `Set-ExecutionPolicy Bypass -Scope Process -Force`.
3. Execute the script by running `.\Advanced_Security_Audit_Config.ps1`

```
Set-ExecutionPolicy Bypass -Scope Process -Force; .\Advanced_Security_Audit_Config.ps1
```

### Remote

The recommended method to execute this script is via Windows Remote Management (WinRM) using the `Invoke-Command` cmdlet for remote execution on target machines.

1. Ensure that WinRM is enabled across your network.
2. Confirm that you have Domain Admin permissions to run the script on remote machines.
3. Execute the script using the `Invoke-Command` cmdlet.

```
Invoke-Command -ComputerName "RemoteComputerName" -FilePath "C:\Path\To\Advanced_Security_Audit_Config.ps1" -Credential (Get-Credential)
```

# Compatibility

The table below outlines the operating systems this script is designed to support.

| **OS Name**            |
| ---------------------- |
| Windows Server 2022    |
| Windows Server 2019    |
| Windows Server 2016    |
| Windows Server 2012    |
| Windows Server 2012 R2 |
| Windows Server 2008    |
| Windows 11             |
| Windows 10             |
| Windows 8.1            |
| Windows 7              |

# Audit Logs

Below is a table of event log titles that are enabled to capture detailed security and system activities for enhanced auditing and forensic logging:

| **Log Name**                                                       |
| ------------------------------------------------------------------ |
| Application                                                        |
| Security                                                           |
| System                                                             |
| Microsoft-Windows-AppLocker/EXE and DLL                            |
| Microsoft-Windows-AppLocker/MSI and Script                         |
| Microsoft-Windows-AppLocker/Packaged app-Deployment                |
| Microsoft-Windows-AppLocker/Packaged app-Execution                 |
| Microsoft-Windows-Bits-Client/Operational                          |
| Microsoft-Windows-CodeIntegrity/Operational                        |
| Microsoft-Windows-Diagnosis-Scripted/Operational                   |
| Microsoft-Windows-DriverFrameworks-UserMode/Operational            |
| Microsoft-Windows-Kernel-Boot/Operational                          |
| Microsoft-Windows-NTLM/Operational                                 |
| Microsoft-Windows-PowerShell/Operational                           |
| Microsoft-Windows-PrintService/Admin                               |
| Microsoft-Windows-PrintService/Operational                         |
| Microsoft-Windows-Security-Auditing                                |
| Microsoft-Windows-Security-Mitigations/KernelMode                  |
| Microsoft-Windows-Security-Mitigations/UserMode                    |
| Microsoft-Windows-SmbClient/Security                               |
| Microsoft-Windows-TaskScheduler/Operational                        |
| Microsoft-Windows-TerminalServices-LocalSessionManager/Operational |
| Microsoft-Windows-Windows Defender/Operational                     |
| Microsoft-Windows-Windows Firewall With Advanced Security/Firewall |
| Microsoft-Windows-WMI-Activity/Operational                         |

# Audit Policies

>[!NOTE] 
>Changes are made to the **local audit policy** immediately and will not reflect in Group Policy.

The following table lists the audit subcategories that have been enabled to ensure thorough monitoring and logging across critical security events:

| Category           | Subcategory                                                                                                                                                                                     | GUID                                   |
| ------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------- |
| Account Logon      | [Credential Validation](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-credential-validation)                          | {0CCE923F-69AE-11D9-BED3-505054503030} |
| Account Logon      | [Kerberos Authentication Service](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-kerberos-authentication-service)      | {0CCE9242-69AE-11D9-BED3-505054503030} |
| Account Logon      | [Kerberos Service Ticket Operation](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-kerberos-service-ticket-operations) | {0CCE9240-69AE-11D9-BED3-505054503030} |
| Account Management | [Computer Account Management](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-computer-account-management)              | {0CCE9236-69AE-11D9-BED3-505054503030} |
| Account Management | [Other Account Management Events](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-other-account-management-events)      | {0CCE923A-69AE-11D9-BED3-505054503030} |
| Account Management | [Security Group Management](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-security-group-management)                  | {0CCE9237-69AE-11D9-BED3-505054503030} |
| Account Management | [User Account Management](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-user-account-management)                      | {0CCE9235-69AE-11D9-BED3-505054503030} |
| Detailed Tracking  | [DPAPI Activity](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-dpapi-activity)                                        | {0CCE922D-69AE-11D9-BED3-505054503030} |
| Detailed Tracking  | [Plug and Play Events](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-pnp-activity)                                    | {0CCE9248-69AE-11D9-BED3-505054503030} |
| Detailed Tracking  | [Process Creation](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-process-creation)                                    | {0CCE922B-69AE-11D9-BED3-505054503030} |
| Detailed Tracking  | [RPC Events](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-rpc-events)                                                | {0CCE922E-69AE-11D9-BED3-505054503030} |
| DS Access          | [Directory Service Access](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-directory-service-access)                    | {0CCE923B-69AE-11D9-BED3-505054503030} |
| DS Access          | [Directory Service Changes](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-directory-service-changes)                  | {0CCE923C-69AE-11D9-BED3-505054503030} |
| Logon/Logoff       | [Account Lockout](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-account-lockout)                                      | {0CCE9217-69AE-11D9-BED3-505054503030} |
| Logon/Logoff       | [Logoff](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-logoff)                                                        | {0CCE9216-69AE-11D9-BED3-505054503030} |
| Logon/Logoff       | [Logon](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-logon)                                                          | {0CCE9215-69AE-11D9-BED3-505054503030} |
| Logon/Logoff       | [Other Logon/Logoff Events](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-other-logonlogoff-events)                   | {0CCE921C-69AE-11D9-BED3-505054503030} |
| Logon/Logoff       | [Special Logon](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-special-logon)                                          | {0CCE921B-69AE-11D9-BED3-505054503030} |
| Object Access      | [Certification Services](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-certification-services)                        | {0CCE9221-69AE-11D9-BED3-505054503030} |
| Object Access      | [Detailed File Share](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-detailed-file-share)                              | {0CCE9244-69AE-11D9-BED3-505054503030} |
| Object Access      | [File Share](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-file-share)                                                | {0CCE9224-69AE-11D9-BED3-505054503030} |
| Object Access      | [Filtering Platform Connection](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-filtering-platform-connection)          | {0CCE9226-69AE-11D9-BED3-505054503030} |
| Object Access      | [Handle Manipulation](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-handle-manipulation)                              | {0CCE9223-69AE-11D9-BED3-505054503030} |
| Object Access      | [Other Object Access Events](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-other-object-access-events)                | {0CCE9227-69AE-11D9-BED3-505054503030} |
| Object Access      | [Removable Storage](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-removable-storage)                                  | {0CCE9245-69AE-11D9-BED3-505054503030} |
| Object Access      | [SAM](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-sam)                                                              | {0CCE9220-69AE-11D9-BED3-505054503030} |
| Policy Change      | [Audit Policy Change](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-audit-policy-change)                              | {0CCE922F-69AE-11D9-BED3-505054503030} |
| Policy Change      | [Authentication Policy Change](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-authentication-policy-change)            | {0CCE9230-69AE-11D9-BED3-505054503030} |
| Policy Change      | [MPSSVC Rule-Level Policy Change](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-mpssvc-rule-level-policy-change)      | {0CCE9232-69AE-11D9-BED3-505054503030} |
| Policy Change      | [Other Policy Change Events](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-other-policy-change-events)                | {0CCE9234-69AE-11D9-BED3-505054503030} |
| System             | [IPsec Driver](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-ipsec-driver)                                            | {0CCE9213-69AE-11D9-BED3-505054503030} |
| System             | [Security State Change](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-security-state-change)                          | {0CCE9210-69AE-11D9-BED3-505054503030} |
| System             | [Security System Extension](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-security-system-extension)                  | {0CCE9211-69AE-11D9-BED3-505054503030} |
| System             | [System Integrity](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-system-integrity)                                    | {0CCE9212-69AE-11D9-BED3-505054503030} |

# References

| Title                                         | Author    | URL                                                                                                                                                       |
| --------------------------------------------- | --------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Greater Visibility Through PowerShell Logging | Mandiant  | https://cloud.google.com/blog/topics/threat-intelligence/greater-visibility/                                                                              |
| Advanced Security Audit Policy Settings       | Microsoft | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/advanced-security-audit-policy-settings |
| Appendix L - Events to Monitor                | Microsoft | https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor                                                        |
| Audit Policy Recommendations                  | Microsoft | https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations                                 |
| Sigma Rules                                   | Sigma     | https://github.com/SigmaHQ/sigma                                                                                                                          |












































































