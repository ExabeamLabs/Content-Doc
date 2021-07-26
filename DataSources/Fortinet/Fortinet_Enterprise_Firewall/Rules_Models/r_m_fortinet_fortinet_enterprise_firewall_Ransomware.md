Vendor: Fortinet
================
### Product: [Fortinet Enterprise Firewall](../ds_fortinet_fortinet_enterprise_firewall.md)
### Use-Case: [Ransomware](../../../../UseCases/uc_ransomware.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   4   |   0    |     2      |      6      |    6    |

| Event Type                    | Rules                                                                                                                                                     | Models |
| ----------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| app-activity                  | <b>T1078 - Valid Accounts</b><br> ↳ <b>Auth-Ransomware-Shost</b>: User authentication or login from a known ransomware IP                                 |        |
| app-activity-failed           | <b>T1078 - Valid Accounts</b><br> ↳ <b>Auth-Ransomware-Shost-Failed</b>: User authentication or login failure from a known ransomware IP                  |        |
| netflow-connection            | <b>T1071 - Application Layer Protocol</b><br> ↳ <b>A-NET-Ransomware-IP</b>: Asset attempted to connect to an IP address which is associated to Ransomware |        |
| network-connection-failed     | <b>T1071 - Application Layer Protocol</b><br> ↳ <b>A-NETF-Ransomware-IP</b>: Asset failed to connect to an IP address which is associated to Ransomware   |        |
| network-connection-successful | <b>T1071 - Application Layer Protocol</b><br> ↳ <b>A-NET-Ransomware-IP</b>: Asset attempted to connect to an IP address which is associated to Ransomware |        |