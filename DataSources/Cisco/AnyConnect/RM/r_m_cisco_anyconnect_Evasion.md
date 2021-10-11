Vendor: Cisco
=============
### Product: [AnyConnect](../ds_cisco_anyconnect.md)
### Use-Case: [Evasion](../../../../UseCases/uc_evasion.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   0    |     2      |      3      |    3    |

| Event Type      | Rules                                                                                                                                                                                                                                                | Models |
| --------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| process-network | <b>T1090.003 - Proxy: Multi-hop Proxy</b><br> ↳ <b>EPA-PI-TorIp</b>: Process has created a connection to known Tor exit node<br><br><b>T1204 - User Execution</b><br> ↳ <b>EPA-PI-TorIp</b>: Process has created a connection to known Tor exit node |        |
| vpn-login       | <b>T1090.003 - Proxy: Multi-hop Proxy</b><br> ↳ <b>Auth-Tor-Shost</b>: User authentication or login from a known TOR IP                                                                                                                              |        |