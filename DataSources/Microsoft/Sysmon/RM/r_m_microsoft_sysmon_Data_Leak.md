Vendor: Microsoft
=================
### Product: [Sysmon](../ds_microsoft_sysmon.md)
### Use-Case: [Data Leak](../../../../UseCases/uc_data_leak.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   7   |   2    |     3      |      6      |    6    |

| Event Type          | Rules    | Models    |
| ---- | ---- | ---- |
| app-activity        | <b>T1114.003 - Email Collection: Email Forwarding Rule</b><br> ↳ <b>EM-InRule-EX</b>: User has created an inbox forwarding rule to forward email to an external domain email<br> ↳ <b>EM-InRule-Public</b>: User has created an inbox forwarding rule to forward email to a public email domain<br> ↳ <b>EM-InRule-Fin</b>: User has created an inbox forwarding rule to forward emails containing financial keywords    |    |
| web-activity-denied | <b>T1071.001 - Application Layer Protocol: Web Protocols</b><br> ↳ <b>WEB-New-File-20-Block</b>: User with no web activity history was blocked from uploading 20MB or more<br><br><b>T1567.002 - Exfiltration Over Web Service: Exfiltration to Cloud Storage</b><br> ↳ <b>WEB-FS</b>: User has accessed a file sharing domain<br> ↳ <b>WEB-OU-FS</b>: One of the top file sharing users in the organization<br> ↳ <b>WEB-OG-FS</b>: One of the top file sharing users in the peer group |  • <b>WEB-OG-FS</b>: File sharing activities of users in the peer group<br> • <b>WEB-OU-FS</b>: File sharing activities of users in the organization |