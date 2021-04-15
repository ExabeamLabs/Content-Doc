Vendor: ESET
============
### Product: [ESET Endpoint Security](../ds_eset_eset_endpoint_security.md)
### Use-Case: [Evasion](../../../../UseCases/uc_evasion.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   4   |   0    |     1      |      7      |    7    |

| Event Type                | Rules                                                                                                                                                                                        | Models |
| ------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| app-login                 | <b>T1090.003 - Proxy: Multi-hop Proxy</b><br> ↳ <b>Auth-Tor-Shost</b>: User authentication or login from a known TOR IP                                                                      |        |
| authentication-failed     | <b>T1090.003 - Proxy: Multi-hop Proxy</b><br> ↳ <b>Auth-Tor-Shost-Failed</b>: User authentication or login failure from a known TOR IP                                                       |        |
| authentication-successful | <b>T1090.003 - Proxy: Multi-hop Proxy</b><br> ↳ <b>Auth-Tor-Shost</b>: User authentication or login from a known TOR IP                                                                      |        |
| failed-logon              | <b>T1090.003 - Proxy: Multi-hop Proxy</b><br> ↳ <b>Auth-Tor-Shost-Failed</b>: User authentication or login failure from a known TOR IP                                                       |        |
| web-activity-denied       | <b>T1090.003 - Proxy: Multi-hop Proxy</b><br> ↳ <b>A-WEB-TorProxy</b>: Asset has accessed a known Tor web proxy<br> ↳ <b>A-WEB-UU-Tor</b>: Asset has accessed a URL containing '/tor/server' |        |