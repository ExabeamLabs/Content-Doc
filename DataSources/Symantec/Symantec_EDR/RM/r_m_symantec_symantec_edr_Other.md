Vendor: Symantec
================
### Product: [Symantec EDR](../ds_symantec_symantec_edr.md)
### Use-Case: [Other](../../../../UseCases/uc_other.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  19   |   4    |     0      |      6      |    6    |

| Event Type   | Rules | Models                                                                                                                                                                                                                                      |
| ------------ | ----- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| file-alert   |       |  • <b>A-EPA-UP-TEMP</b>: Processes executed from TEMP directories on this asset                                                                                                                                                             |
| file-write   |       |  • <b>A-FW-ProcessName-FileName</b>: File creations for process<br> • <b>A-EPA-UP-TEMP</b>: Processes executed from TEMP directories on this asset                                                                                          |
| remote-logon |       |  • <b>A-EPA-UP-TEMP</b>: Processes executed from TEMP directories on this asset<br> • <b>A-KL-UToE</b>: Ticket options and encryption type combination for asset<br> • <b>A-AE-NTLM</b>: Models the NTLM hostnames seen in the organization |