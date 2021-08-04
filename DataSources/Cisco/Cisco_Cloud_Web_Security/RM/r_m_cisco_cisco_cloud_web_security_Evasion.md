Vendor: Cisco
=============
### Product: [Cisco Cloud Web Security](../ds_cisco_cisco_cloud_web_security.md)
### Use-Case: [Evasion](../../../../UseCases/uc_evasion.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   3   |   1    |     2      |      2      |    2    |

| Event Type           | Rules                                                                                                                                                                                                                                                                                                                                                           | Models                                                                                            |
| -------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| web-activity-allowed | <b>T1071.001 - Application Layer Protocol: Web Protocols</b><br> ↳ <b>WEB-OUa-OS-F</b>: First web activity using this operating system for the organization<br><br><b>T1090.003 - Proxy: Multi-hop Proxy</b><br> ↳ <b>A-WEB-TorProxy</b>: Asset has accessed a known Tor web proxy<br> ↳ <b>A-WEB-UU-Tor</b>: Asset has accessed a URL containing '/tor/server' |  • <b>WEB-OUa-OS</b>: Top operating systems being used to connect to the web for the organization |
| web-activity-denied  | <b>T1090.003 - Proxy: Multi-hop Proxy</b><br> ↳ <b>A-WEB-TorProxy</b>: Asset has accessed a known Tor web proxy<br> ↳ <b>A-WEB-UU-Tor</b>: Asset has accessed a URL containing '/tor/server'                                                                                                                                                                    |                                                                                                   |