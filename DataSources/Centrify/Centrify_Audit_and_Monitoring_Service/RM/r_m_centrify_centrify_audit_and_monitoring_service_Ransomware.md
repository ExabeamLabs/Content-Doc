Vendor: Centrify
================
### Product: [Centrify Audit and Monitoring Service](../ds_centrify_centrify_audit_and_monitoring_service.md)
### Use-Case: [Ransomware](../../../../UseCases/uc_ransomware.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   0    |     2      |      3      |    3    |

| Event Type    | Rules    | Models |
| ---- | ---- | ------ |
| authentication-successful | <b>T1078 - Valid Accounts</b><br> ↳ <b>Auth-Ransomware-Shost</b>: User authentication or login from a known ransomware IP    |        |
| file-write    | <b>T1486 - Data Encrypted for Impact</b><br> ↳ <b>FA-EXT</b>: A file has been written and is suspected of Ransomware on host |        |