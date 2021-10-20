Vendor: Check Point
===================
### Product: [NGFW](../ds_check_point_ngfw.md)
### Use-Case: [Other](../../../../UseCases/uc_other.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  23   |   4    |     0      |     11      |   11    |

| Event Type                    | Rules | Models                                                                                                                                                |
| ----------------------------- | ----- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| local-logon                   |       |  • <b>A-EPA-UP-TEMP</b>: Processes executed from TEMP directories on this asset<br> • <b>A-AL-DhU</b>: Users per Host                                 |
| network-alert                 |       |  • <b>A-EPA-UP-TEMP</b>: Processes executed from TEMP directories on this asset                                                                       |
| network-connection-failed     |       |  • <b>A-NET-OdPort-Outbound</b>: Outbound destination ports per organization<br> • <b>A-NET-HdPort-Outbound</b>: Outbound destination ports per asset |
| network-connection-successful |       |  • <b>A-NET-OdPort-Outbound</b>: Outbound destination ports per organization<br> • <b>A-NET-HdPort-Outbound</b>: Outbound destination ports per asset |