Vendor: Citrix
==============
### Product: [Citrix Endpoint Management](../ds_citrix_citrix_endpoint_management.md)
### Use-Case: [Ransomware](../../../../UseCases/uc_ransomware.md)

| Rules | Models | MITRE ATT&CK® TTPs | Event Types | Parsers |
|:-----:|:------:|:------------------:|:-----------:|:-------:|
|   1   |   0    |         1          |      2      |    2    |

| Event Type   | Rules    | Models |
| ---- | ---- | ------ |
| app-activity | <b>T1078 - Valid Accounts</b><br> ↳ <b>Auth-Ransomware-Shost</b>: User authentication or login from a known ransomware IP |        |
| remote-logon | <b>T1078 - Valid Accounts</b><br> ↳ <b>Auth-Ransomware-Shost</b>: User authentication or login from a known ransomware IP |        |