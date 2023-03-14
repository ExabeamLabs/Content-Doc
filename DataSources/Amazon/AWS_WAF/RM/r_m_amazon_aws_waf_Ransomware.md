Vendor: Amazon
==============
### Product: [AWS WAF](../ds_amazon_aws_waf.md)
### Use-Case: [Ransomware](../../../../UseCases/uc_ransomware.md)

| Rules | Models | MITRE ATT&CK® TTPs | Event Types | Parsers |
|:-----:|:------:|:------------------:|:-----------:|:-------:|
|   1   |   0    |         1          |      2      |    2    |

| Event Type    | Rules    | Models |
| ---- | ---- | ------ |
| web-activity-allowed | <b>T1071.001 - Application Layer Protocol: Web Protocols</b><br> ↳ <b>WEB-UI-Ransomware</b>: User attempted to connect to IP address which is associated to Ransomware |        |
| web-activity-denied  | <b>T1071.001 - Application Layer Protocol: Web Protocols</b><br> ↳ <b>WEB-UI-Ransomware</b>: User attempted to connect to IP address which is associated to Ransomware |        |