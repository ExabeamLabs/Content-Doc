Vendor: Cisco
=============
### Product: [Cisco Adaptive Security Appliance](../ds_cisco_cisco_adaptive_security_appliance.md)
### Use-Case: [Data Exfiltration via Web](../../../../UseCases/uc_data_exfiltration_via_web.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   0    |     2      |     13      |   13    |

| Event Type          | Rules                                                                                                                                              | Models |
| ------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| process-created     | <b>T1505.003 - Server Software Component: Web Shell</b><br> ↳ <b>A-WebShell-WebServer</b>: Possible web server web shell detected on this asset    |        |
| web-activity-denied | <b>T1030 - Data Transfer Size Limits</b><br> ↳ <b>New-File-20-Block</b>: User with no web activity history was blocked from uploading 20MB or more |        |