Vendor: Oracle
==============
### Product: [Oracle Solaris](../ds_oracle_oracle_solaris.md)
### Use-Case: [Compromised Credentials](../../../../UseCases/uc_compromised_credentials.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  43   |   7    |     7      |      2      |    2    |

| Event Type      | Rules                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    | Models                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| --------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| process-created | <b>T1040 - Network Sniffing</b><br> ↳ <b>A-EPA-SNIFF</b>: Network sniffing tool has been found running on this asset<br> ↳ <b>A-EPA-OH-SNIFF-F</b>: First time this asset has had an execution of a network sniffing tool<br> ↳ <b>A-EPA-OH-SNIFF-A</b>: Abnormal asset running network sniffing tool<br> ↳ <b>A-EPA-OZ-SNIFF-F</b>: First zone on which network sniffing tool was run<br> ↳ <b>A-EPA-OZ-SNIFF-A</b>: Abnormal zone on which network sniffing tool was run<br> ↳ <b>EPA-OU-SNIFF-F</b>: First time this user has run a network sniffing tool<br> ↳ <b>EPA-OU-SNIFF-A</b>: Abnormal user has run a network sniffing tool<br> ↳ <b>EPA-OG-SNIFF-F</b>: First time this peer group has run a network sniffing tool<br> ↳ <b>EPA-OG-SNIFF-A</b>: Abnormal peer group running a network sniffing tool<br> ↳ <b>EPA-OH-SNIFF-F</b>: First time this host has run a network sniffing tool<br> ↳ <b>EPA-OH-SNIFF-A</b>: Abnormal host running a network sniffing tool<br> ↳ <b>EPA-OZ-SNIFF-F</b>: First time this network zone on which a networking sniffing tool run.<br> ↳ <b>EPA-OZ-SNIFF-A</b>: Abnormal network zone on which network sniffing tool was run<br> ↳ <b>DLL-AppData</b>: DLL loaded from 'AppData(slash)Local' path<br><br><b>T1003 - OS Credential Dumping</b><br> ↳ <b>A-SecX-Tool-Exec</b>: SecurityXploded Tool execution detected on this asset<br> ↳ <b>A-CreateMiniDump-Hacktool</b>: CreateMiniDump Hacktool detected on this asset.<br> ↳ <b>A-LSASS-Mem-Dump</b>: LSASS Memory Dumping detected on this asset<br> ↳ <b>A-Proc-Dump-Comsvcs</b>: Process Dump via Rundll32 and Comsvcs.dll detected on this asset<br> ↳ <b>A-AD-Diagnostic-Tool</b>: Invocation of Active Directory Diagnostic Tool (ntdsutil.exe) on this asset<br> ↳ <b>A-GRAB-REG-HIVES</b>: Grabbing Sensitive Hives via Reg Utility on this asset<br> ↳ <b>A-ShadowCP-SymLink</b>: Shadow Copies Access via Symlink on this asset<br> ↳ <b>A-POSS-SPN-ENUMERATION</b>: Possible SPN Enumeration on this asset<br> ↳ <b>A-Cmdkey-Cred-Recon</b>: Cmdkey Cached Credentials Recon on this asset<br> ↳ <b>A-NSniff-Cred</b>: Potential network sniffing was observed on this asset.<br> ↳ <b>EPA-UH-Pen-F</b>: Known pentest tool used<br> ↳ <b>Mimikatz-process</b>: A highly dangerous attacker tool, Mimikatz, has been used<br> ↳ <b>SecX-Tool-Exec</b>: SecurityXploded Tool execution detected<br> ↳ <b>CreateMiniDump-Hacktool</b>: CreateMiniDump Hacktool<br> ↳ <b>EPA-SNIFF</b>: Network sniffing tool has been run by this user<br> ↳ <b>Proc-Dump-Comsvcs</b>: Process Dump via Rundll32 and Comsvcs.dll<br> ↳ <b>AD-Diagnostic-Tool</b>: Invocation of Active Directory Diagnostic Tool (ntdsutil.exe)<br> ↳ <b>Sus-Procdump</b>: Suspicious Use of Procdump<br> ↳ <b>GRAB-REG-HIVES</b>: Grabbing Sensitive Hives via Reg Utility<br> ↳ <b>ShadowCP-SymLink</b>: Shadow Copies Access via Symlink<br> ↳ <b>POSS-SPN-ENUMERATION</b>: Possible SPN Enumeration<br> ↳ <b>OG-SYSVOL-F</b>: Suspicious SYSVOL Domain Group Policy Access for the first time for this peer group<br> ↳ <b>NSniff-Cred</b>: Potential network sniffing was observed<br><br><b>T1036 - Masquerading</b><br> ↳ <b>A-AD-Diagnostic-Tool</b>: Invocation of Active Directory Diagnostic Tool (ntdsutil.exe) on this asset<br> ↳ <b>A-GRAB-REG-HIVES</b>: Grabbing Sensitive Hives via Reg Utility on this asset<br> ↳ <b>AD-Diagnostic-Tool</b>: Invocation of Active Directory Diagnostic Tool (ntdsutil.exe)<br> ↳ <b>GRAB-REG-HIVES</b>: Grabbing Sensitive Hives via Reg Utility<br><br><b>T1547.004 - T1547.004</b><br> ↳ <b>A-NotPetya-Activity</b>: NotPetya Ransomware Activity detected on this asset<br> ↳ <b>NotPetya-Activity</b>: NotPetya Ransomware Activity detected<br><br><b>T1016 - System Network Configuration Discovery</b><br> ↳ <b>WINCMD-Route</b>: 'Route' program used<br> ↳ <b>WINCMD-Netsh</b>: 'Netsh' program used<br> ↳ <b>WINCMD-Arp</b>: 'Arp' program used<br><br><b>T1003.003 - T1003.003</b><br> ↳ <b>A-ServiceName-ServiceCmdline-F</b>: First time binary command line for this service on this asset. |  • <b>EPA-OG-SYSVOL</b>: SYSVOL domain group policy access by group in the organization<br> • <b>EPA-OZ-SNIFF</b>: Network Zones on which network sniffing tools are run<br> • <b>EPA-OH-SNIFF</b>: Hosts that have been found to be running network sniffing tools<br> • <b>EPA-OG-SNIFF</b>: Peer groups that are running network sniffing tools<br> • <b>EPA-OU-SNIFF</b>: Users that are running network sniffing tools<br> • <b>EPA-UH-Pen</b>: Malicious tools used by user<br> • <b>A-ServiceName-ServiceCmdline</b>: Service Executable Files on the asset |