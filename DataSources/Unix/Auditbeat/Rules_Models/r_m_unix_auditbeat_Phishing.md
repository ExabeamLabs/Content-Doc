Vendor: Unix
============
### Product: [Auditbeat](../ds_unix_auditbeat.md)
### Use-Case: [Phishing](../../../../UseCases/uc_phishing.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   1    |     1      |      6      |    6    |

| Event Type             | Rules                                                                                                                          | Models |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------------------ | ------ |
| process-network        | <b>T1071 - Application Layer Protocol</b><br> ↳ <b>NET-TI-H-Outbound</b>: Outbound connection to a known malicious host        |        |
| process-network-failed | <b>T1071 - Application Layer Protocol</b><br> ↳ <b>NETF-TI-IP-Outbound</b>: Outbound failed connection to a known malicious IP |        |