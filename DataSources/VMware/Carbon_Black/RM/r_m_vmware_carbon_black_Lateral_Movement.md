Vendor: VMware
==============
### Product: [Carbon Black](../ds_vmware_carbon_black.md)
### Use-Case: [Lateral Movement](../../../../UseCases/uc_lateral_movement.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  44   |   2    |     14     |      1      |    1    |

| Event Type      | Rules                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          | Models                                                                                                                                                            |
| --------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| process-created | <b>T1021.003 - T1021.003</b><br> ↳ <b>A-PC-ParentName-ProcessName-DCOM-F</b>: First time child process creation for DCOM associated process on this asset.<br> ↳ <b>A-PC-ParentName-ProcessName-DCOM-A</b>: Abnormal child process creation for DCOM associated process on the asset.<br> ↳ <b>A-DCOMActivation-Known</b>: Remote DCOM activation under DcomLaunch service on this asset.<br> ↳ <b>PC-ParentName-ProcessName-DCOM-F</b>: First time child process creation for DCOM associated process<br> ↳ <b>PC-ParentName-ProcessName-DCOM-A</b>: Abnormal child process creation for DCOM associated process.<br> ↳ <b>DCOMActivation-Known</b>: Remote DCOM activation under DcomLaunch service<br><br><b>T1190 - Exploit Public Fasing Application</b><br> ↳ <b>EPA-DLL</b>: Dll loaded from a temp folder via PowerShell<br><br><b>T1210 - Exploitation of Remote Services</b><br> ↳ <b>EPA-DLL</b>: Dll loaded from a temp folder via PowerShell<br><br><b>T1090 - Proxy</b><br> ↳ <b>A-DNS-Exfiltration-Tools-Exec</b>: Well-known DNS Exfiltration tools were executed on this asset.<br> ↳ <b>A-MMC-Spawn-Win-Shell</b>: MMC (Microsoft Management Console) started a Windows command line executable on this asset.<br> ↳ <b>Netsh-Connections-Win-Firewall</b>: Netsh commands were used to allow incoming connections by Port or Application on Windows Firewall.<br> ↳ <b>Netsh-Port-Fwd</b>: Netsh commands were used to configure port forwarding.<br><br><b>T1021 - Remote Services</b><br> ↳ <b>A-Impacket-Lateral-Detection</b>: Activity related to Impacket framework using wmiexec, dcomexe, or smbexec processes via command line have been found on this asset.<br> ↳ <b>Netsh-RDP-Port-Fwd</b>: Netsh commands used to configure port forwarding for port 3389, used for RDP, were detected.<br><br><b>T1047 - Windows Management Instrumentation</b><br> ↳ <b>A-Shim-Installation</b>: Possible installation of a 'shim' using sdbinst.exe on this asset<br> ↳ <b>Impacket-Lateral-Detection</b>: Activity related to Impacket framework using wmiexec, dcomexe, or smbexec processes via command line have been found.<br><br><b>T1175 - T1175</b><br> ↳ <b>A-Shim-Installation</b>: Possible installation of a 'shim' using sdbinst.exe on this asset<br> ↳ <b>Impacket-Lateral-Detection</b>: Activity related to Impacket framework using wmiexec, dcomexe, or smbexec processes via command line have been found.<br><br><b>T1021.002 - Remote Services: SMB/Windows Admin Shares</b><br> ↳ <b>A-TurlaGroup-LateralMovement</b>: Artifacts from the ATP 'Turla Group' have been observed on this asset<br> ↳ <b>TurlaGroup-LateralMovement</b>: Artifacts from the ATP 'Turla Group' have been observed<br><br><b>T1059 - Command and Scripting Interperter</b><br> ↳ <b>A-TurlaGroup-LateralMovement</b>: Artifacts from the ATP 'Turla Group' have been observed on this asset<br> ↳ <b>ZxShell</b>: Known backdoor software, ZxShell, possibly loaded<br> ↳ <b>TurlaGroup-LateralMovement</b>: Artifacts from the ATP 'Turla Group' have been observed<br><br><b>T1083 - File and Directory Discovery</b><br> ↳ <b>A-TurlaGroup-LateralMovement</b>: Artifacts from the ATP 'Turla Group' have been observed on this asset<br> ↳ <b>TurlaGroup-LateralMovement</b>: Artifacts from the ATP 'Turla Group' have been observed<br><br><b>T1135 - Network Share Discovery</b><br> ↳ <b>A-TurlaGroup-LateralMovement</b>: Artifacts from the ATP 'Turla Group' have been observed on this asset<br> ↳ <b>TurlaGroup-LateralMovement</b>: Artifacts from the ATP 'Turla Group' have been observed<br><br><b>T1218.011 - Signed Binary Proxy Execution: Rundll32</b><br> ↳ <b>ZxShell</b>: Known backdoor software, ZxShell, possibly loaded<br><br><b>T1021.001 - Remote Services: Remote Desktop Protocol</b><br> ↳ <b>A-Suspicious-RDP-TSCON</b>: Suspicious usage of RDP using tscon.exe on this asset<br> ↳ <b>Suspicious-RDP-TSCON</b>: Suspicious usage of RDP using tscon.exe<br><br><b>T1219 - Remote Access Software</b><br> ↳ <b>A-EPA-RAT-SSI</b>: Splashtop remote desktop access service installed on this asset<br> ↳ <b>A-EPA-RAT-TI</b>: TeamViewer remote desktop access agent installed on this asset<br> ↳ <b>A-EPA-RAT-SSS</b>: Splashtop remote desktop access service started on this asset<br> ↳ <b>A-EPA-RAT-SI</b>: Splashtop remote desktop access agent installed on this asset<br> ↳ <b>A-EPA-RAT-GSS</b>: GoToMyPC remote desktop access service started on this asset<br> ↳ <b>A-EPA-RAT-GSI</b>: GoToMyPC remote desktop access service installed on this asset<br> ↳ <b>A-EPA-RAT-TSI</b>: TeamViewer remote desktop access service installed on this asset<br> ↳ <b>A-EPA-RAT-LSS</b>: LogMeIn remote desktop access service started on this asset<br> ↳ <b>A-EPA-RAT-LSI</b>: LogMeIn remote desktop access service installed on this asset<br> ↳ <b>A-EPA-RAT-LI</b>: LogMeIn remote desktop access agent installed on this asset<br> ↳ <b>A-EPA-RAT-GI</b>: GoToMyPC remote desktop access agent installed on this asset<br> ↳ <b>A-UAC-IE-INVOKE</b>: Windows UAC consent dialogue was used to invoke an Internet Explorer process running as Local SYSTEM<br> ↳ <b>A-TSCON-LocalSystem</b>: Tscon.exe was executed as Local System on this asset<br> ↳ <b>EPA-RAT-LSS</b>: LogMeIn remote desktop access service started by this user<br> ↳ <b>EPA-RAT-LI</b>: LogMeIn remote desktop access agent installed by this user<br> ↳ <b>EPA-RAT-SSI</b>: Splashtop remote desktop access service installed by this user<br> ↳ <b>EPA-RAT-SI</b>: Splashtop remote desktop access agent installed by this user<br> ↳ <b>EPA-RAT-TSI</b>: TeamViewer remote desktop access service installed by this user<br> ↳ <b>EPA-RAT-GI</b>: GoToMyPC remote desktop access agent installed by this user<br> ↳ <b>EPA-RAT-TI</b>: TeamViewer remote desktop access agent installed by this user<br> ↳ <b>EPA-RAT-GSS</b>: GoToMyPC remote desktop access service started by this user<br> ↳ <b>EPA-RAT-TSS</b>: TeamViewer remote desktop access service started by this user<br> ↳ <b>EPA-RAT-SSS</b>: Splashtop remote desktop access service started by this user<br> ↳ <b>EPA-RAT-LSI</b>: LogMeIn remote desktop access service installed by this user |  • <b>PC-ParentName-ProcessName</b>: Child processes created by a parent process<br> • <b>A-PC-ParentName-ProcessName</b>: Processes for parent parent processes. |