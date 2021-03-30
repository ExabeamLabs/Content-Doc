Vendor: Check Point
===================
### Product: [Check Point Security Gateway](../ds_check_point_check_point_security_gateway.md)
### Use-Case: [Ransomware Detection](../../../../UseCases/uc_ransomware_detection.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   4   |   1    |     2      |      2      |    2    |

| Event Type       | Rules                                                                                                                                                                                                                                                                                                                                   | Models                                                |
| ---------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------- |
| failed-vpn-login | <b>T1188 - T1188</b><br> ↳ <b>Auth-Tor-Shost-Failed</b>: User authentication or login failure from a known TOR IP<br> ↳ <b>Auth-Blacklist-Shost-Failed</b>: User authentication or login failure from a known blacklisted IP<br> ↳ <b>Auth-Ransomware-Shost-Failed</b>: User authentication or login failure from a known ransomware IP |                                                       |
| vpn-login        | <b>T1188 - T1188</b><br> ↳ <b>Auth-Tor-Shost</b>: User authentication or login from a known TOR IP<br> ↳ <b>Auth-Blacklist-Shost</b>: User authentication or login from a known blacklisted IP<br> ↳ <b>Auth-Ransomware-Shost</b>: User authentication or login from a known ransomware IP                                              |                                                       |
| vpn-logout       | <b>T1048 - Exfiltration Over Alternative Protocol</b><br> ↳ <b>EM-BSum-in</b>: Abnormal size of incoming emails                                                                                                                                                                                                                         |  • <b>EM-BSum-in</b>: Sum of bytes in incoming emails |