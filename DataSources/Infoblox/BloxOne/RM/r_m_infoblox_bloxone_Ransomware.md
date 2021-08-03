Vendor: Infoblox
================
### Product: [BloxOne](../ds_infoblox_bloxone.md)
### Use-Case: [Ransomware](../../../../UseCases/uc_ransomware.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   3   |   0    |     2      |      8      |    8    |

| Event Type                    | Rules                                                                                                                                                     | Models |
| ----------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| app-activity                  | <b>T1078 - Valid Accounts</b><br> ↳ <b>Auth-Ransomware-Shost</b>: User authentication or login from a known ransomware IP                                 |        |
| app-login                     | <b>T1078 - Valid Accounts</b><br> ↳ <b>Auth-Ransomware-Shost</b>: User authentication or login from a known ransomware IP                                 |        |
| network-connection-failed     | <b>T1071 - Application Layer Protocol</b><br> ↳ <b>A-NETF-Ransomware-IP</b>: Asset failed to connect to an IP address which is associated to Ransomware   |        |
| network-connection-successful | <b>T1071 - Application Layer Protocol</b><br> ↳ <b>A-NET-Ransomware-IP</b>: Asset attempted to connect to an IP address which is associated to Ransomware |        |
| remote-logon                  | <b>T1078 - Valid Accounts</b><br> ↳ <b>Auth-Ransomware-Shost</b>: User authentication or login from a known ransomware IP                                 |        |