Vendor: Palo Alto Networks
==========================
### Product: [Palo Alto Aperture](../ds_palo_alto_networks_palo_alto_aperture.md)
### Use-Case: [Data Exfiltration](../../../../UseCases/uc_data_exfiltration.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  21   |   13   |     6      |      7      |    7    |

| Event Type   | Rules                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | Models                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| ------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| app-activity | <b>T1098.002 - Account Manipulation: Exchange Email Delegate Permissions</b><br> ↳ <b>InB-Perm-N-F</b>: First time a user has given mailbox permissions on another mailbox that is not their own<br><br><b>T1114.003 - Email Collection: Email Forwarding Rule</b><br> ↳ <b>EM-InRule-EX</b>: User has created an inbox forwarding rule to forward email to an external domain email<br> ↳ <b>EM-InRule-Public</b>: User has created an inbox forwarding rule to forward email to a public email domain                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |  • <b>EM-InB-Perm-N</b>: Models users who give mailbox permissions                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| dlp-alert    | <b>T1204 - User Execution</b><br> ↳ <b>DLP-UBp-F</b>: First blocked process for the user<br><br><b>T1048 - Exfiltration Over Alternative Protocol</b><br> ↳ <b>DLP-OU-ALERT-F</b>: First DLP alert triggered for this user<br> ↳ <b>DLP-OU-ALERT-A</b>: Abnormal user triggering DLP alert<br> ↳ <b>DLP-OG-ALERT-F</b>: First DLP alert triggered for peer group in the organization<br> ↳ <b>DLP-OG-ALERT-A</b>: Abnormal peer group triggering DLP alert in the organization<br> ↳ <b>DLP-OA-F</b>: First DLP policy violation from asset for the organization<br><br><b>T1020 - Automated Exfiltration</b><br> ↳ <b>DLP-AN-ALERT-F</b>: First DLP alert name on the asset<br> ↳ <b>DLP-AN-ALERT-A</b>: Abnormal DLP alert name on the asset<br> ↳ <b>DLP-ON-ALERT-F</b>: First DLP alert (by name) in the organization<br> ↳ <b>DLP-ON-ALERT-A</b>: Abnormal DLP alert (by name) in the organization<br> ↳ <b>DLP-ZN-ALERT-F</b>: First DLP alert (by name) in the zone<br> ↳ <b>DLP-ZN-ALERT-A</b>: Abnormal DLP alert (by name) in the zone<br> ↳ <b>DLP-HN-ALERT-F</b>: First DLP alert (by name) in the asset<br> ↳ <b>DLP-HN-ALERT-A</b>: Abnormal DLP alert (by name) in the asset<br> ↳ <b>DLP-OA-ALERT-F</b>: First DLP alert triggered for asset in the organization |  • <b>DLP-UBp</b>: Processes that are blocked from execution for the user<br> • <b>DLP-OA</b>: Assets on which DLP policy violations occurred in the organization<br> • <b>DLP-OG-ALERT</b>: Peer groups triggering DLP alerts in the organization<br> • <b>DLP-OU-ALERT</b>: Users triggering DLP alerts in the organization<br> • <b>A-DLP-OA-ALERT</b>: Assets triggering DLP alerts in the organization<br> • <b>A-DLP-HN-ALERT</b>: DLP alert names triggered in the asset<br> • <b>A-DLP-ZN-ALERT</b>: DLP alert names triggered in the zone<br> • <b>A-DLP-ON-ALERT</b>: DLP alert names triggered in the organization<br> • <b>A-DLP-AN-ALERT</b>: DLP alert names on asset |
| file-delete  | <b>T1083 - File and Directory Discovery</b><br> ↳ <b>FA-FG-F</b>: First access to folder for group<br> ↳ <b>FA-OG-A</b>: Abnormal access to source code files for user in the peer group<br> ↳ <b>FA-SFU-F</b>: First access to folder containing source code by user                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |  • <b>FA-SFU</b>: Source code folder access by users<br> • <b>FA-OG</b>: Users accessing source code files in the peer group<br> • <b>FA-FG</b>: Folder access by groups                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| file-read    | <b>T1083 - File and Directory Discovery</b><br> ↳ <b>FA-FG-F</b>: First access to folder for group<br> ↳ <b>FA-OG-A</b>: Abnormal access to source code files for user in the peer group<br> ↳ <b>FA-SFU-F</b>: First access to folder containing source code by user                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |  • <b>FA-SFU</b>: Source code folder access by users<br> • <b>FA-OG</b>: Users accessing source code files in the peer group<br> • <b>FA-FG</b>: Folder access by groups                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| file-write   | <b>T1083 - File and Directory Discovery</b><br> ↳ <b>FA-FG-F</b>: First access to folder for group<br> ↳ <b>FA-OG-A</b>: Abnormal access to source code files for user in the peer group<br> ↳ <b>FA-SFU-F</b>: First access to folder containing source code by user                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |  • <b>FA-SFU</b>: Source code folder access by users<br> • <b>FA-OG</b>: Users accessing source code files in the peer group<br> • <b>FA-FG</b>: Folder access by groups                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |