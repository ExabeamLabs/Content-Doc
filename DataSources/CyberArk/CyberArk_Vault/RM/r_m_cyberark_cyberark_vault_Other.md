Vendor: CyberArk
================
### Product: [CyberArk Vault](../ds_cyberark_cyberark_vault.md)
### Use-Case: [Other](../../../../UseCases/uc_other.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  127  |   6    |     0      |     15      |   15    |

| Event Type      | Rules | Models                                                                                                                                                                                                                                         |
| --------------- | ----- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| account-switch  |       |  • <b>A-EPA-UP-TEMP</b>: Processes executed from TEMP directories on this asset                                                                                                                                                                |
| file-write      |       |  • <b>A-FW-ProcessName-FileName</b>: File creations for process<br> • <b>A-EPA-UP-TEMP</b>: Processes executed from TEMP directories on this asset                                                                                             |
| process-created |       |  • <b>A-PC-Process-Hash</b>: Hashes used to create processes on the asset.<br> • <b>A-PC-ParentName-ProcessName</b>: Processes for parent parent processes.<br> • <b>A-EPA-UP-TEMP</b>: Processes executed from TEMP directories on this asset |
| remote-logon    |       |  • <b>A-EPA-UP-TEMP</b>: Processes executed from TEMP directories on this asset<br> • <b>A-KL-UToE</b>: Ticket options and encryption type combination for asset<br> • <b>A-AE-NTLM</b>: Models the NTLM hostnames seen in the organization    |