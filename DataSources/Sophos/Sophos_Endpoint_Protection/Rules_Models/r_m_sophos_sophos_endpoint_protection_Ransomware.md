Vendor: Sophos
==============
### Product: [Sophos Endpoint Protection](../ds_sophos_sophos_endpoint_protection.md)
### Use-Case: [Ransomware](../../../../UseCases/uc_ransomware.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   0    |     2      |     10      |   10    |

| Event Type                | Rules                                                                                                                                                   | Models |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| failed-vpn-login          | <b>T1078 - Valid Accounts</b><br> ↳ <b>Auth-Ransomware-Shost-Failed</b>: User authentication or login failure from a known ransomware IP                |        |
| network-connection-failed | <b>T1071 - Application Layer Protocol</b><br> ↳ <b>A-NETF-Ransomware-IP</b>: Asset failed to connect to an IP address which is associated to Ransomware |        |
| vpn-login                 | <b>T1078 - Valid Accounts</b><br> ↳ <b>Auth-Ransomware-Shost</b>: User authentication or login from a known ransomware IP                               |        |