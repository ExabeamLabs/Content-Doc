Vendor: Microsoft
=================
### Product: [Azure Active Directory](../ds_microsoft_azure_active_directory.md)
### Use-Case: [Other](../../../../UseCases/uc_other.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  115  |   4    |     0      |     11      |   11    |

| Event Type      | Rules | Models                                                                                                                                                                                                                                         |
| --------------- | ----- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| member-added    |       |  • <b>A-AM-DhU-system</b>: System accounts performing account management activities                                                                                                                                                            |
| process-created |       |  • <b>A-PC-Process-Hash</b>: Hashes used to create processes on the asset.<br> • <b>A-PC-ParentName-ProcessName</b>: Processes for parent parent processes.<br> • <b>A-EPA-UP-TEMP</b>: Processes executed from TEMP directories on this asset |
| security-alert  |       |  • <b>A-EPA-UP-TEMP</b>: Processes executed from TEMP directories on this asset                                                                                                                                                                |