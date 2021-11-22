Vendor: Unix
============
### Product: [Unix](../ds_unix_unix.md)
### Use-Case: [Other](../../../../UseCases/uc_other.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  134  |   7    |     0      |     28      |   28    |

| Event Type             | Rules | Models                                                                                                                                                                                                                                         |
| ---------------------- | ----- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| account-creation       |       |  • <b>A-AM-DhU-system</b>: System accounts performing account management activities                                                                                                                                                            |
| batch-logon            |       |  • <b>A-EPA-UP-TEMP</b>: Processes executed from TEMP directories on this asset                                                                                                                                                                |
| dlp-alert              |       |  • <b>A-EPA-UP-TEMP</b>: Processes executed from TEMP directories on this asset                                                                                                                                                                |
| kerberos-logon         |       |  • <b>A-KL-UToE</b>: Ticket options and encryption type combination for asset                                                                                                                                                                  |
| local-logon            |       |  • <b>A-EPA-UP-TEMP</b>: Processes executed from TEMP directories on this asset                                                                                                                                                                |
| member-added           |       |  • <b>A-AM-DhU-system</b>: System accounts performing account management activities                                                                                                                                                            |
| netflow-connection     |       |  • <b>A-NETFLOW-dHdP</b>: Destination Ports per asset                                                                                                                                                                                          |
| network-alert          |       |  • <b>A-EPA-UP-TEMP</b>: Processes executed from TEMP directories on this asset                                                                                                                                                                |
| process-created        |       |  • <b>A-PC-Process-Hash</b>: Hashes used to create processes on the asset.<br> • <b>A-PC-ParentName-ProcessName</b>: Processes for parent parent processes.<br> • <b>A-EPA-UP-TEMP</b>: Processes executed from TEMP directories on this asset |
| process-created-failed |       |  • <b>A-PC-Process-Hash</b>: Hashes used to create processes on the asset.<br> • <b>A-EPA-UP-TEMP</b>: Processes executed from TEMP directories on this asset                                                                                  |
| remote-logon           |       |  • <b>A-EPA-UP-TEMP</b>: Processes executed from TEMP directories on this asset<br> • <b>A-KL-UToE</b>: Ticket options and encryption type combination for asset<br> • <b>A-AE-NTLM</b>: Models the NTLM hostnames seen in the organization    |
| security-alert         |       |  • <b>A-EPA-UP-TEMP</b>: Processes executed from TEMP directories on this asset                                                                                                                                                                |