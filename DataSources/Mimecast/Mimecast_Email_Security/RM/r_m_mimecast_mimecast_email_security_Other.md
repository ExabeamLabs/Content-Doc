Vendor: Mimecast
================
### Product: [Mimecast Email Security](../ds_mimecast_mimecast_email_security.md)
### Use-Case: [Other](../../../../UseCases/uc_other.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  11   |   2    |     0      |     14      |   14    |

| Event Type    | Rules | Models                                                                                                                                             |
| ------------- | ----- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| file-write    |       |  • <b>A-FW-ProcessName-FileName</b>: File creations for process<br> • <b>A-EPA-UP-TEMP</b>: Processes executed from TEMP directories on this asset |
| network-alert |       |  • <b>A-EPA-UP-TEMP</b>: Processes executed from TEMP directories on this asset                                                                    |
| process-alert |       |  • <b>A-EPA-UP-TEMP</b>: Processes executed from TEMP directories on this asset                                                                    |