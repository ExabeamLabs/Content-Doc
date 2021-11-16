Vendor: Trend Micro
===================
### Product: [Deep Security Agent](../ds_trend_micro_deep_security_agent.md)
### Use-Case: [Other](../../../../UseCases/uc_other.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  10   |   3    |     0      |      3      |    3    |

| Event Type                    | Rules | Models                                                                                                                                                |
| ----------------------------- | ----- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| network-connection-successful |       |  • <b>A-NET-OdPort-Outbound</b>: Outbound destination ports per organization<br> • <b>A-NET-HdPort-Outbound</b>: Outbound destination ports per asset |
| privileged-object-access      |       |  • <b>A-EPA-UP-TEMP</b>: Processes executed from TEMP directories on this asset                                                                       |
| security-alert                |       |  • <b>A-EPA-UP-TEMP</b>: Processes executed from TEMP directories on this asset                                                                       |