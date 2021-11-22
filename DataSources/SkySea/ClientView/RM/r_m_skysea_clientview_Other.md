Vendor: SkySea
==============
### Product: [ClientView](../ds_skysea_clientview.md)
### Use-Case: [Other](../../../../UseCases/uc_other.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  14   |   2    |     0      |     12      |   12    |

| Event Type     | Rules | Models                                                                                                                                             |
| -------------- | ----- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| file-write     |       |  • <b>A-FW-ProcessName-FileName</b>: File creations for process<br> • <b>A-EPA-UP-TEMP</b>: Processes executed from TEMP directories on this asset |
| security-alert |       |  • <b>A-EPA-UP-TEMP</b>: Processes executed from TEMP directories on this asset                                                                    |