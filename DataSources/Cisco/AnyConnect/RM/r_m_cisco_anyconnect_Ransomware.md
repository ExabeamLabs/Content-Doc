Vendor: Cisco
=============
### Product: [AnyConnect](../ds_cisco_anyconnect.md)
### Use-Case: [Ransomware](../../../../UseCases/uc_ransomware.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   0    |     2      |      3      |    3    |

| Event Type      | Rules                                                                                                                                                     | Models |
| --------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| process-network | <b>T1071 - Application Layer Protocol</b><br> ↳ <b>A-NET-Ransomware-IP</b>: Asset attempted to connect to an IP address which is associated to Ransomware |        |
| vpn-login       | <b>T1078 - Valid Accounts</b><br> ↳ <b>Auth-Ransomware-Shost</b>: User authentication or login from a known ransomware IP                                 |        |