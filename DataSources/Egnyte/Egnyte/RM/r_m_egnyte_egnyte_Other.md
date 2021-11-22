Vendor: Egnyte
==============
### Product: [Egnyte](../ds_egnyte_egnyte.md)
### Use-Case: [Other](../../../../UseCases/uc_other.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  10   |   4    |     0      |      8      |    8    |

| Event Type   | Rules | Models                                                                                                                                                                                                                                      |
| ------------ | ----- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| file-write   |       |  • <b>A-FW-ProcessName-FileName</b>: File creations for process<br> • <b>A-EPA-UP-TEMP</b>: Processes executed from TEMP directories on this asset                                                                                          |
| remote-logon |       |  • <b>A-EPA-UP-TEMP</b>: Processes executed from TEMP directories on this asset<br> • <b>A-KL-UToE</b>: Ticket options and encryption type combination for asset<br> • <b>A-AE-NTLM</b>: Models the NTLM hostnames seen in the organization |