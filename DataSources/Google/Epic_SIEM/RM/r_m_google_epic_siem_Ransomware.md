Vendor: Google
==============
### Product: [Epic SIEM](../ds_google_epic_siem.md)
### Use-Case: [Ransomware](../../../../UseCases/uc_ransomware.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   3   |   0    |     2      |      5      |    5    |

| Event Type            | Rules                                                                                                                                    | Models |
| --------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| app-login             | <b>T1078 - Valid Accounts</b><br> ↳ <b>Auth-Ransomware-Shost</b>: User authentication or login from a known ransomware IP                |        |
| authentication-failed | <b>T1078 - Valid Accounts</b><br> ↳ <b>Auth-Ransomware-Shost-Failed</b>: User authentication or login failure from a known ransomware IP |        |
| file-write            | <b>T1486 - Data Encrypted for Impact</b><br> ↳ <b>FA-EXT</b>: A file has been written and is suspected of Ransomware on host             |        |