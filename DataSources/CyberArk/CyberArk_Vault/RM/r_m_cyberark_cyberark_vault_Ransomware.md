Vendor: CyberArk
================
### Product: [CyberArk Vault](../ds_cyberark_cyberark_vault.md)
### Use-Case: [Ransomware](../../../../UseCases/uc_ransomware.md)

| Rules | Models | MITRE ATT&CK® TTPs | Event Types | Parsers |
|:-----:|:------:|:------------------:|:-----------:|:-------:|
|   3   |   0    |         2          |      7      |    7    |

| Event Type          | Rules    | Models |
| ---- | ---- | ------ |
| app-activity        | <b>T1078 - Valid Accounts</b><br> ↳ <b>Auth-Ransomware-Shost</b>: User authentication or login from a known ransomware IP    |        |
| app-activity-failed | <b>T1078 - Valid Accounts</b><br> ↳ <b>Auth-Ransomware-Shost-Failed</b>: User authentication or login failure from a known ransomware IP |        |
| app-login    | <b>T1078 - Valid Accounts</b><br> ↳ <b>Auth-Ransomware-Shost</b>: User authentication or login from a known ransomware IP    |        |
| failed-app-login    | <b>T1078 - Valid Accounts</b><br> ↳ <b>Auth-Ransomware-Shost-Failed</b>: User authentication or login failure from a known ransomware IP |        |
| failed-logon        | <b>T1078 - Valid Accounts</b><br> ↳ <b>Auth-Ransomware-Shost-Failed</b>: User authentication or login failure from a known ransomware IP |        |
| file-write          | <b>T1486 - Data Encrypted for Impact</b><br> ↳ <b>FA-EXT</b>: A file has been written and is suspected of Ransomware on host    |        |
| remote-logon        | <b>T1078 - Valid Accounts</b><br> ↳ <b>Auth-Ransomware-Shost</b>: User authentication or login from a known ransomware IP    |        |