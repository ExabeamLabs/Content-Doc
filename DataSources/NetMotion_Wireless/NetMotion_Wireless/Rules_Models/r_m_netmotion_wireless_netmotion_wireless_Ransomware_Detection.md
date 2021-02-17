Vendor: NetMotion Wireless
==========================
### Product: [NetMotion Wireless](../ds_netmotion_wireless_netmotion_wireless.md)
### Use-Case: [Ransomware Detection](../../../../UseCases/uc_ransomware_detection.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   4   |   1    |     3      |      2      |    2    |

| Event Type | Rules                                                                                                                                                                                                                                                                                                                                                | Models |
| ---------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| vpn-login  | <b>T1078 - Valid Accounts</b><br> ↳ <b>Auth-Blacklist-Shost</b>: User authentication or login from a known blacklisted IP<br> ↳ <b>Auth-Ransomware-Shost</b>: User authentication or login from a known ransomware IP<br><br><b>T1090.003 - Proxy: Multi-hop Proxy</b><br> ↳ <b>Auth-Tor-Shost</b>: User authentication or login from a known TOR IP |        |
| vpn-logout | <b>T1566 - Phishing</b><br> ↳ <b>EM-BSum-in</b>: Abnormal size of incoming emails                                                                                                                                                                                                                                                                    |        |