Vendor: Google
==============
### Product: [Exabeam Advanced Analytics](../ds_google_exabeam_advanced_analytics.md)
### Use-Case: [Other](../../../../UseCases/uc_other.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   7   |   2    |     0      |     15      |   15    |

| Event Type     | Rules | Models                                                                                                                                             |
| -------------- | ----- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| file-write     |       |  • <b>A-FW-ProcessName-FileName</b>: File creations for process<br> • <b>A-EPA-UP-TEMP</b>: Processes executed from TEMP directories on this asset |
| security-alert |       |  • <b>A-EPA-UP-TEMP</b>: Processes executed from TEMP directories on this asset                                                                    |