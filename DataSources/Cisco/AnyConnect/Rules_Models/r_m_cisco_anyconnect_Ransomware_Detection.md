Vendor: Cisco
=============
### Product: [AnyConnect](../ds_cisco_anyconnect.md)
### Use-Case: [Ransomware Detection](../../../../UseCases/uc_ransomware_detection.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  19   |   7    |     5      |      3      |    3    |

| Event Type      | Rules                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | Models                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| process-network | <b>T1204 - User Execution</b><br> ↳ <b>A-EPA-HP-F</b>: First execution of process on asset<br> ↳ <b>A-EPA-HP-A</b>: Abnormal execution of process on asset<br> ↳ <b>A-EPA-ZP-A</b>: Abnormal execution of process for the asset in this zone<br> ↳ <b>A-EPA-ZP-F</b>: First execution of process for the asset in this zone<br> ↳ <b>A-EPA-OP-F</b>: First execution of process for the asset in this organization<br> ↳ <b>A-EPA-OP-A</b>: Abnormal execution of process for the asset in this organization<br> ↳ <b>EPA-TEMP-DIRECTORY-F</b>: First time process has been executed from a temporary directory by this user during endpoint activity<br> ↳ <b>EPA-TEMP-DIRECTORY-A</b>: Abnormal process has been executed from a temporary directory by this user during endpoint activity<br><br><b>T1071 - Application Layer Protocol</b><br> ↳ <b>NET-TI-H-Outbound</b>: Outbound connection to a known malicious host<br> ↳ <b>NET-OdZ-Inbound-F</b>: First inbound connection to zone.<br> ↳ <b>NET-OdZ-Inbound-A</b>: Abnormal inbound connection to zone.<br><br><b>T1036 - Masquerading</b><br> ↳ <b>A-EPA-HPP-F</b>: First parent-process combination on asset<br> ↳ <b>A-EPA-HPP-A</b>: Abnormal parent-process combination on asset<br> ↳ <b>A-EPA-OPP-F</b>: First parent-process combination in this organization<br> ↳ <b>A-EPA-OPP-A</b>: Abnormal parent-process combination in this organization |  • <b>EPA-UP-TEMP</b>: Process executable TEMP directories for this user during endpoint activity<br> • <b>A-NET-OdZ-Inbound</b>: Network zones with inbound communication in the organization<br> • <b>A-EPA-UP-TEMP</b>: Processes executed from TEMP directories on this asset<br> • <b>A-EPA-OPP</b>: Parent processes in the organization<br> • <b>A-EPA-HPP</b>: Parent processes per host on this asset<br> • <b>A-EPA-ZP</b>: Processes in the zone on asset |
| vpn-login       | <b>T1188 - T1188</b><br> ↳ <b>Auth-Tor-Shost</b>: User authentication or login from a known TOR IP<br> ↳ <b>Auth-Blacklist-Shost</b>: User authentication or login from a known blacklisted IP<br> ↳ <b>Auth-Ransomware-Shost</b>: User authentication or login from a known ransomware IP                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| vpn-logout      | <b>T1048 - Exfiltration Over Alternative Protocol</b><br> ↳ <b>EM-BSum-in</b>: Abnormal size of incoming emails                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |  • <b>EM-BSum-in</b>: Sum of bytes in incoming emails                                                                                                                                                                                                                                                                                                                                                                                                                |