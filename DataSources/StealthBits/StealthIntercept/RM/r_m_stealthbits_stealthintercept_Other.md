Vendor: StealthBits
===================
### Product: [StealthIntercept](../ds_stealthbits_stealthintercept.md)
### Use-Case: [Other](../../../../UseCases/uc_other.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  15   |   4    |     0      |     10      |   10    |

| Event Type                | Rules | Models                                                                                                                                             |
| ------------------------- | ----- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| file-write                |       |  • <b>A-FW-ProcessName-FileName</b>: File creations for process<br> • <b>A-EPA-UP-TEMP</b>: Processes executed from TEMP directories on this asset |
| member-added              |       |  • <b>A-AM-DhU-system</b>: System accounts performing account management activities                                                                |
| network-connection-failed |       |  • <b>A-NET-OdPort-Outbound</b>: Outbound destination ports per organization                                                                       |