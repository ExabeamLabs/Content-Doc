Vendor: Forescout
=================
### Product: [Forescout CounterACT](../ds_forescout_forescout_counteract.md)
### Use-Case: [Compromised Credentials](../../../../UseCases/uc_compromised_credentials.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  14   |   11   |     3      |      6      |    6    |

| Event Type                    | Rules                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | Models                                                                                                                                                                                                                                                                                                                                                         |
| ----------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| file-delete                   | <b>T1083 - File and Directory Discovery</b><br> ↳ <b>FA-UA-UI-F</b>: First file activity from ISP<br> ↳ <b>FA-UA-UC-A</b>: Abnormal file activity from country for user<br> ↳ <b>FA-UA-GC-F</b>: First file activity from country for group<br> ↳ <b>FA-FG-F</b>: First access to folder for group<br> ↳ <b>FA-OG-A</b>: Abnormal access to source code files for user in the peer group<br> ↳ <b>FA-SFU-F</b>: First access to folder containing source code by user                                                                                                               |  • <b>FA-SFU</b>: Source code folder access by users<br> • <b>FA-OG</b>: Users accessing source code files in the peer group<br> • <b>FA-FG</b>: Folder access by groups<br> • <b>FA-UA-GC</b>: Countries for peer groups file activities<br> • <b>FA-UA-UC</b>: Countries for user file activity<br> • <b>FA-UA-UI-new</b>: ISP of users during file activity |
| network-alert                 | <b>T1027.005 - Obfuscated Files or Information: Indicator Removal from Tools</b><br> ↳ <b>A-ALERT-Other</b>: Alert on asset<br> ↳ <b>A-ALERT-Critical</b>: Security Alert on a critical asset<br> ↳ <b>A-IDS-OLA-F</b>: First network alert on asset with no previous alerts for organization<br> ↳ <b>A-IDS-ZLA-A</b>: Abnormal network alert for asset for zone<br> ↳ <b>A-IDS-OLZ-F</b>: First network alert for zone in the organization<br> ↳ <b>A-IDS-HdPort-A</b>: Abnormal network alert on port for asset<br> ↳ <b>A-IDS-ALERT-6</b>: Six distinct network alerts on asset |  • <b>A-IDS-HdPort</b>: Destination ports on which network alerts have triggered for the asset<br> • <b>A-IDS-OLZ</b>: Zones in which network alerts are triggered in the organization<br> • <b>A-IDS-ZLA</b>: Assets that triggered network alerts in the zone<br> • <b>A-IDS-OLA</b>: Assets that triggered network alerts in the organization               |
| network-connection-successful | <b>T1046 - Network Service Scanning</b><br> ↳ <b>NETFLOW-OsH-SweepScan-A</b>: Abnormal for asset to access 20 assets in 10 seconds                                                                                                                                                                                                                                                                                                                                                                                                                                                  |  • <b>A-NETFLOW-OsH-Scanners</b>: Assets that access multiple assets within seconds in the organization                                                                                                                                                                                                                                                        |