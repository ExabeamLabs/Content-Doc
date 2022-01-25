Vendor: Cisco
=============
### Product: [Cisco Firepower](../ds_cisco_cisco_firepower.md)
### Use-Case: [Ransomware](../../../../UseCases/uc_ransomware.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   4   |   0    |     2      |     11      |   11    |

| Event Type                    | Rules                                                                                                                                                                                                                                                                  | Models |
| ----------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| authentication-successful     | <b>T1078 - Valid Accounts</b><br> ↳ <b>Auth-Ransomware-Shost</b>: User authentication or login from a known ransomware IP                                                                                                                                              |        |
| netflow-connection            | <b>T1071 - Application Layer Protocol</b><br> ↳ <b>A-NET-Ransomware-IP</b>: Asset attempted to connect to an IP address which is associated to Ransomware                                                                                                              |        |
| network-connection-failed     | <b>T1071 - Application Layer Protocol</b><br> ↳ <b>A-NETF-Ransomware-IP</b>: Asset failed to connect to an IP address which is associated to Ransomware                                                                                                                |        |
| network-connection-successful | <b>T1071 - Application Layer Protocol</b><br> ↳ <b>A-NET-Ransomware-IP</b>: Asset attempted to connect to an IP address which is associated to Ransomware                                                                                                              |        |
| web-activity-allowed          | <b>T1071 - Application Layer Protocol</b><br> ↳ <b>A-NET-Ransomware-IP</b>: Asset attempted to connect to an IP address which is associated to Ransomware<br> ↳ <b>A-WEB-Ransomware-Domain</b>: Asset attempted to connect to domain which is associated to Ransomware |        |
| web-activity-denied           | <b>T1071 - Application Layer Protocol</b><br> ↳ <b>A-NETF-Ransomware-IP</b>: Asset failed to connect to an IP address which is associated to Ransomware<br> ↳ <b>A-WEB-Ransomware-Domain</b>: Asset attempted to connect to domain which is associated to Ransomware   |        |