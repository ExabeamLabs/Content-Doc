Vendor: Ipswitch
================
### Product: [MoveIt DMZ](../ds_ipswitch_moveit_dmz.md)
### Use-Case: [Other](../../../../UseCases/uc_other.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  11   |   4    |     0      |      9      |    9    |

| Event Type             | Rules | Models                                                                                                                                                        |
| ---------------------- | ----- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| file-write             |       |  • <b>A-FW-ProcessName-FileName</b>: File creations for process<br> • <b>A-EPA-UP-TEMP</b>: Processes executed from TEMP directories on this asset            |
| member-added           |       |  • <b>A-AM-DhU-system</b>: System accounts performing account management activities                                                                           |
| process-created-failed |       |  • <b>A-PC-Process-Hash</b>: Hashes used to create processes on the asset.<br> • <b>A-EPA-UP-TEMP</b>: Processes executed from TEMP directories on this asset |