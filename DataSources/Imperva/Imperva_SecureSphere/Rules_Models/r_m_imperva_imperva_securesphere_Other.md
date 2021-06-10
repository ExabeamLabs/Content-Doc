Vendor: Imperva
===============
### Product: [Imperva SecureSphere](../ds_imperva_imperva_securesphere.md)
### Use-Case: [Other](../../../../UseCases/uc_other.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  82   |   39   |     8      |     10      |   10    |

| Event Type       | Rules                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | Models                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| ---------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| app-login        | <b>T1078 - Valid Accounts</b><br> ↳ <b>AE-UA-F</b>: First activity type for user<br> ↳ <b>Auth-Blacklist-Shost</b>: User authentication or login from a known blacklisted IP<br> ↳ <b>Auth-Ransomware-Shost</b>: User authentication or login from a known ransomware IP<br> ↳ <b>NEW-USER-F</b>: User with no event history<br> ↳ <b>APP-Account-deactivated</b>: Activity from a de-activated user account<br> ↳ <b>APP-UApp-F</b>: First login or activity within an application for user<br> ↳ <b>APP-UApp-A</b>: Abnormal login or activity within an application for user<br> ↳ <b>APP-AppU-F</b>: First login to an application for a user with no history<br> ↳ <b>APP-F-SA-NC</b>: New service account access to application<br> ↳ <b>APP-AppG-F</b>: First login to an application for group<br> ↳ <b>APP-GApp-A</b>: Abnormal login to an application for group<br> ↳ <b>APP-UTi</b>: Abnormal user activity time<br> ↳ <b>APP-UAg-F</b>: First user agent string for user<br> ↳ <b>APP-UAg-2</b>: Second new user agent string for user<br> ↳ <b>APP-UAg-3</b>: More than two new user agents used by the user in the same session<br> ↳ <b>APP-UsH-F</b>: First source asset for user in application<br> ↳ <b>APP-UsH-A</b>: Abnormal source asset for user in application<br> ↳ <b>APP-UId-F</b>: First use of client Id for user<br> ↳ <b>APP-IdU-F</b>: Reuse of client Id<br> ↳ <b>APP-AppSz-F</b>: First application access from network zone<br><br><b>T1078 - Valid Accounts</b><b>T1133 - External Remote Services</b><br> ↳ <b>UA-UC-A</b>: Abnormal activity from country for user<br> ↳ <b>UA-GC-F</b>: First activity from country for group<br> ↳ <b>UA-OC-F</b>: First activity from country for organization<br> ↳ <b>UA-UC-new</b>: Abnormal country for user by new user<br> ↳ <b>UA-UC-Suspicious</b>: Activity from suspicious country<br> ↳ <b>UA-UC-Two</b>: Activity from two different countries<br><br><b>T1090.003 - Proxy: Multi-hop Proxy</b><br> ↳ <b>Auth-Tor-Shost</b>: User authentication or login from a known TOR IP                                                                                                                                                                                                                                                                                                                                                                                         |  • <b>APP-AppSz</b>: Source zones per application<br> • <b>APP-IdU</b>: User per Client Id<br> • <b>APP-UId</b>: Client Id per User<br> • <b>APP-UsH</b>: User's machines accessing applications<br> • <b>APP-UAg</b>: User Agent Strings<br> • <b>APP-UTi</b>: Application activity time for user<br> • <b>APP-GApp</b>: Group Logons to Applications<br> • <b>APP-AppG</b>: Groups per Application<br> • <b>APP-AppU</b>: User Logons to Applications<br> • <b>APP-UApp</b>: Applications per User<br> • <b>UA-UC</b>: Countries for user activity<br> • <b>UA-OC</b>: Countries for organization<br> • <b>UA-GC</b>: Countries for peer groups<br> • <b>AE-UA</b>: All activity for users                                                                                                                                             |
| database-alert   | <b>T1213 - Data from Information Repositories</b><br> ↳ <b>DB-UN-ALERT-F</b>: First database alert name for user<br> ↳ <b>DB-UN-ALERT-A</b>: Abnormal database alert name for user<br> ↳ <b>DB-ON-ALERT-F</b>: First database alert name in the organization<br> ↳ <b>DB-ON-ALERT-A</b>: Abnormal database alert name in the organization<br> ↳ <b>DB-GN-ALERT-F</b>: First database alert name in the peer group<br> ↳ <b>DB-GN-ALERT-A</b>: Abnormal database alert name in the peer group<br> ↳ <b>DB-OU-ALERT-F</b>: First database alert triggered for this user in the organization<br> ↳ <b>DB-OU-ALERT-A</b>: Abnormal user triggering database alert in the organization<br> ↳ <b>DB-OG-ALERT-F</b>: First database alert triggered for peer group in the organization<br> ↳ <b>DB-OG-ALERT-A</b>: Abnormal peer group triggering database alert in the organization<br><br><b>T1204 - User Execution</b><br> ↳ <b>EPA-TEMP-DIRECTORY-F</b>: First execution of this process from a temporary directory on this asset<br> ↳ <b>EPA-TEMP-DIRECTORY-A</b>: Abnormal execution of this process from a temporary directory<br><br><b>T1078 - Valid Accounts</b><br> ↳ <b>DB-AN-ALERT-F</b>: First database alert name on the asset<br> ↳ <b>DB-AN-ALERT-A</b>: Abnormal database alert name on the asset<br> ↳ <b>DB-ZN-ALERT-A</b>: Abnormal database alert (by name) in the zone<br> ↳ <b>DB-ZN-ALERT-F</b>: First database alert (by name) in the zone<br> ↳ <b>DB-OA-ALERT-F</b>: First database alert triggered for asset in the organization<br> ↳ <b>DB-ZA-ALERT-F</b>: First database alert triggered for asset inb the zone<br> ↳ <b>DB-ZA-ALERT-A</b>: Abnormal asset triggering database alert for zone                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |  • <b>DB-OG-ALERT</b>: Peer groups triggering database alerts in the organization<br> • <b>DB-OU-ALERT</b>: Users triggering database alerts in the organization<br> • <b>DB-GN-ALERT</b>: Database alert names in the peer group<br> • <b>DB-ON-ALERT</b>: Database alert names in the organization<br> • <b>DB-UN-ALERT</b>: Database alert names for user<br> • <b>A-EPA-UP-TEMP</b>: Processes executed from TEMP directories on this asset<br> • <b>A-DB-ZA-ALERT</b>: Assets triggering database alerts in the zone<br> • <b>A-DB-OA-ALERT</b>: Assets triggering database alerts in the organization<br> • <b>A-DB-ZN-ALERT</b>: Database alert names triggered in the zone<br> • <b>A-DB-ON-ALERT</b>: Database alert names triggered in the organization<br> • <b>A-DB-AN-ALERT</b>: Database alert names on asset              |
| failed-app-login | <b>T1078 - Valid Accounts</b><br> ↳ <b>Auth-Ransomware-Shost-Failed</b>: User authentication or login failure from a known ransomware IP<br> ↳ <b>APP-Account-deactivated</b>: Activity from a de-activated user account<br> ↳ <b>APP-F-FL</b>: Failed login to application<br><br><b>T1090.003 - Proxy: Multi-hop Proxy</b><br> ↳ <b>Auth-Tor-Shost-Failed</b>: User authentication or login failure from a known TOR IP<br> ↳ <b>Auth-Blacklist-Shost-Failed</b>: User authentication or login failure from a known blacklisted IP<br><br><b>T1133 - External Remote Services</b><br> ↳ <b>FA-UC-F</b>: Failed activity from a new country<br> ↳ <b>FA-GC-F</b>: First Failed activity in session from country in which peer group has never had a successful activity                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |  • <b>UA-GC</b>: Countries for peer groups<br> • <b>UA-UC</b>: Countries for user activity                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| network-alert    | <b>T1204 - User Execution</b><br> ↳ <b>EPA-TEMP-DIRECTORY-F</b>: First execution of this process from a temporary directory on this asset<br> ↳ <b>EPA-TEMP-DIRECTORY-A</b>: Abnormal execution of this process from a temporary directory<br> ↳ <b>DEF-TEMP-DIRECTORY-F</b>: First time process has been executed from a temporary directory by this user<br> ↳ <b>DEF-TEMP-DIRECTORY-A</b>: Abnormal process has been executed from a temporary directory by this user<br><br><b>T1027.005 - Obfuscated Files or Information: Indicator Removal from Tools</b><br> ↳ <b>A-ALERT-Other</b>: Alert on asset<br> ↳ <b>A-ALERT-Critical</b>: Security Alert on a critical asset<br> ↳ <b>A-IDS-OLA-F</b>: First network alert on asset with no previous alerts for organization<br> ↳ <b>A-IDS-ZLA-A</b>: Abnormal network alert for asset for zone<br> ↳ <b>A-IDS-OLZ-F</b>: First network alert for zone in the organization<br> ↳ <b>A-IDS-HdPort-A</b>: Abnormal network alert on port for asset<br> ↳ <b>A-IDS-ALERT-6</b>: Six distinct network alerts on asset                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |  • <b>AE-UP-TEMP</b>: Process executable TEMP directories for this user during a session<br> • <b>A-IDS-HdPort</b>: Destination ports on which network alerts have triggered for the asset<br> • <b>A-IDS-OLZ</b>: Zones in which network alerts are triggered in the organization<br> • <b>A-IDS-ZLA</b>: Assets that triggered network alerts in the zone<br> • <b>A-IDS-OLA</b>: Assets that triggered network alerts in the organization<br> • <b>A-EPA-UP-TEMP</b>: Processes executed from TEMP directories on this asset                                                                                                                                                                                                                                                                                                          |
| security-alert   | <b>T1078 - Valid Accounts</b><br> ↳ <b>SA-AN-ALERT-F</b>: First security alert name on the asset<br> ↳ <b>SA-AN-ALERT-A</b>: Abnormal security alert name on the asset<br> ↳ <b>SA-ON-ALERT-F</b>: First security alert (by name) in the organization<br> ↳ <b>SA-ON-ALERT-A</b>: Abnormal security alert (by name) in the organization<br> ↳ <b>SA-ZN-ALERT-F</b>: First security alert (by name) in the zone<br> ↳ <b>SA-ZN-ALERT-A</b>: Abnormal security alert (by name) in the zone<br> ↳ <b>SA-HN-ALERT-F</b>: First security alert (by name) in the asset<br> ↳ <b>SA-HN-ALERT-A</b>: Abnormal security alert (by name) in the asset<br> ↳ <b>SA-OA-ALERT-A</b>: Abnormal asset triggering security alert for organization<br> ↳ <b>SA-OU-ALERT-F</b>: First security alert triggered for this user in the organization<br> ↳ <b>SA-OU-ALERT-A</b>: Abnormal user triggering security alert in the organization<br> ↳ <b>SA-OG-ALERT-F</b>: First security alert triggered for peer group in the organization<br> ↳ <b>SA-OG-ALERT-A</b>: Abnormal peer group triggering security alert in the organization<br> ↳ <b>SA-UA-F</b>: First security alert name for user<br> ↳ <b>SA-UA-A</b>: Abnormal security alert name for user<br> ↳ <b>SA-OA-F</b>: First security alert name in the organization<br> ↳ <b>SA-OA-A</b>: Abnormal security alert name in the organization<br><br><b>T1204 - User Execution</b><br> ↳ <b>EPA-TEMP-DIRECTORY-F</b>: First execution of this process from a temporary directory on this asset<br> ↳ <b>EPA-TEMP-DIRECTORY-A</b>: Abnormal execution of this process from a temporary directory<br> ↳ <b>DEF-TEMP-DIRECTORY-F</b>: First time process has been executed from a temporary directory by this user<br> ↳ <b>DEF-TEMP-DIRECTORY-A</b>: Abnormal process has been executed from a temporary directory by this user<br><br><b>T1027.005 - Obfuscated Files or Information: Indicator Removal from Tools</b><br> ↳ <b>A-ALERT-DISTINCT-NAMES</b>: Various security alerts on asset<br> ↳ <b>A-ALERT-Critical</b>: Security Alert on a critical asset<br> ↳ <b>ALERT-DL</b>: DL Correlation rule alert on asset accessed by this user<br><br><b>T1068 - Exploitation for Privilege Escalation</b><br> ↳ <b>ALERT-EXEC</b>: Security violation by Executive<br><br><b>T1059.001 - Command and Scripting Interperter: PowerShell</b><br> ↳ <b>A-ALERT-COMPROMISED-POWERSHELL</b>: Powershell and security alerts |  • <b>SA-OA</b>: Security alert names in the organization<br> • <b>SA-UA</b>: Security alert names for user<br> • <b>AE-UP-TEMP</b>: Process executable TEMP directories for this user during a session<br> • <b>SA-OG-ALERT</b>: Peer groups triggering security alerts in the organization<br> • <b>SA-OU-ALERT</b>: Users triggering security alerts in the organization<br> • <b>A-EPA-UP-TEMP</b>: Processes executed from TEMP directories on this asset<br> • <b>A-SA-OA-ALERT</b>: Assets triggering security alerts in the organization<br> • <b>A-SA-HN-ALERT</b>: Security alert names triggered by the asset<br> • <b>A-SA-ZN-ALERT</b>: Security alert names triggered in the zone<br> • <b>A-SA-ON-ALERT</b>: Security alert names triggered in the organization<br> • <b>A-SA-AN-ALERT</b>: Security alert names on asset |