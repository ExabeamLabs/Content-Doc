Vendor: Digital Guardian
========================
### Product: [Digital Guardian Endpoint Protection](../ds_digital_guardian_digital_guardian_endpoint_protection.md)
### Use-Case: [Other](../../../../UseCases/uc_other.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  18   |   3    |     0      |     14      |   14    |

| Event Type                    | Rules | Models                                                                                                                                             |
| ----------------------------- | ----- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| file-write                    |       |  • <b>A-FW-ProcessName-FileName</b>: File creations for process<br> • <b>A-EPA-UP-TEMP</b>: Processes executed from TEMP directories on this asset |
| local-logon                   |       |  • <b>A-EPA-UP-TEMP</b>: Processes executed from TEMP directories on this asset                                                                    |
| network-connection-failed     |       |  • <b>A-NET-OdPort-Outbound</b>: Outbound destination ports per organization                                                                       |
| network-connection-successful |       |  • <b>A-NET-OdPort-Outbound</b>: Outbound destination ports per organization                                                                       |