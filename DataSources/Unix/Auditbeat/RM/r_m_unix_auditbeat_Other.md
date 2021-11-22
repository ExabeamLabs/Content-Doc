Vendor: Unix
============
### Product: [Auditbeat](../ds_unix_auditbeat.md)
### Use-Case: [Other](../../../../UseCases/uc_other.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  22   |   5    |     0      |      6      |    6    |

| Event Type             | Rules | Models                                                                                                                                                                                                                                      |
| ---------------------- | ----- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| process-created-failed |       |  • <b>A-PC-Process-Hash</b>: Hashes used to create processes on the asset.<br> • <b>A-EPA-UP-TEMP</b>: Processes executed from TEMP directories on this asset                                                                               |
| process-network        |       |  • <b>A-NET-OdPort-Outbound</b>: Outbound destination ports per organization<br> • <b>A-EPA-UP-TEMP</b>: Processes executed from TEMP directories on this asset                                                                             |
| remote-logon           |       |  • <b>A-EPA-UP-TEMP</b>: Processes executed from TEMP directories on this asset<br> • <b>A-KL-UToE</b>: Ticket options and encryption type combination for asset<br> • <b>A-AE-NTLM</b>: Models the NTLM hostnames seen in the organization |