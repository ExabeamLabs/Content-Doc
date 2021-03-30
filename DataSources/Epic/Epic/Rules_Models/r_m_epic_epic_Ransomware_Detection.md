Vendor: Epic
============
### Product: [Epic](../ds_epic_epic.md)
### Use-Case: [Ransomware Detection](../../../../UseCases/uc_ransomware_detection.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   6   |   0    |     1      |      6      |    6    |

| Event Type                | Rules                                                                                                                                                                                                                                                                                                                                   | Models |
| ------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| app-activity              | <b>T1188 - T1188</b><br> ↳ <b>Auth-Tor-Shost</b>: User authentication or login from a known TOR IP<br> ↳ <b>Auth-Blacklist-Shost</b>: User authentication or login from a known blacklisted IP<br> ↳ <b>Auth-Ransomware-Shost</b>: User authentication or login from a known ransomware IP                                              |        |
| app-login                 | <b>T1188 - T1188</b><br> ↳ <b>Auth-Tor-Shost</b>: User authentication or login from a known TOR IP<br> ↳ <b>Auth-Blacklist-Shost</b>: User authentication or login from a known blacklisted IP<br> ↳ <b>Auth-Ransomware-Shost</b>: User authentication or login from a known ransomware IP                                              |        |
| authentication-successful | <b>T1188 - T1188</b><br> ↳ <b>Auth-Tor-Shost</b>: User authentication or login from a known TOR IP<br> ↳ <b>Auth-Blacklist-Shost</b>: User authentication or login from a known blacklisted IP<br> ↳ <b>Auth-Ransomware-Shost</b>: User authentication or login from a known ransomware IP                                              |        |
| failed-app-login          | <b>T1188 - T1188</b><br> ↳ <b>Auth-Tor-Shost-Failed</b>: User authentication or login failure from a known TOR IP<br> ↳ <b>Auth-Blacklist-Shost-Failed</b>: User authentication or login failure from a known blacklisted IP<br> ↳ <b>Auth-Ransomware-Shost-Failed</b>: User authentication or login failure from a known ransomware IP |        |