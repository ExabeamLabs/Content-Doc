Vendor: InfoWatch
=================
### Product: [InfoWatch](../ds_infowatch_infowatch.md)
### Use-Case: [Evasion](../../../../UseCases/uc_evasion.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   4   |   1    |     2      |      6      |    6    |

| Event Type           | Rules                                                                                                                                                                                                                                                                                                                                                           | Models                                                                                            |
| -------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| app-login            | <b>T1090.003 - Proxy: Multi-hop Proxy</b><br> ↳ <b>Auth-Tor-Shost</b>: User authentication or login from a known TOR IP                                                                                                                                                                                                                                         |                                                                                                   |
| web-activity-allowed | <b>T1071.001 - Application Layer Protocol: Web Protocols</b><br> ↳ <b>WEB-OUa-OS-F</b>: First web activity using this operating system for the organization<br><br><b>T1090.003 - Proxy: Multi-hop Proxy</b><br> ↳ <b>A-WEB-TorProxy</b>: Asset has accessed a known Tor web proxy<br> ↳ <b>A-WEB-UU-Tor</b>: Asset has accessed a URL containing '/tor/server' |  • <b>WEB-OUa-OS-New</b>: Top operating systems being used to connect to the web for organization |