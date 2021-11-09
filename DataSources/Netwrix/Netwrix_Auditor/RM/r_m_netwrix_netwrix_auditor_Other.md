Vendor: Netwrix
===============
### Product: [Netwrix Auditor](../ds_netwrix_netwrix_auditor.md)
### Use-Case: [Other](../../../../UseCases/uc_other.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   9   |   3    |     0      |     15      |   15    |

| Event Type     | Rules | Models                                                                                                                                             |
| -------------- | ----- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| file-write     |       |  • <b>A-FW-ProcessName-FileName</b>: File creations for process<br> • <b>A-EPA-UP-TEMP</b>: Processes executed from TEMP directories on this asset |
| member-added   |       |  • <b>A-AM-DhU-system</b>: System accounts performing account management activities                                                                |
| security-alert |       |  • <b>A-EPA-UP-TEMP</b>: Processes executed from TEMP directories on this asset                                                                    |