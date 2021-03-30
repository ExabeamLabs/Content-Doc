Vendor: ProxySG
===============
### Product: [ProxySG](../ds_proxysg_proxysg.md)
### Use-Case: [Other](../../../../UseCases/uc_other.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   4   |   1    |     2      |      1      |    1    |

| Event Type            | Rules                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | Models                                       |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------- |
| authentication-failed | <b>T1188 - T1188</b><br> ↳ <b>Auth-Tor-Shost-Failed</b>: User authentication or login failure from a known TOR IP<br> ↳ <b>Auth-Blacklist-Shost-Failed</b>: User authentication or login failure from a known blacklisted IP<br> ↳ <b>Auth-Ransomware-Shost-Failed</b>: User authentication or login failure from a known ransomware IP<br><br><b>T1133 - External Remote Services</b><br> ↳ <b>FA-UC-F</b>: First Failed activity in session from country in which user has never had a successful activity |  • <b>UA-UC</b>: Countries for user activity |