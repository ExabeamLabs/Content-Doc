Vendor: Web Application Firewall
================================
### Product: [Web Application Firewall](../ds_web_application_firewall_web_application_firewall.md)
### Use-Case: [Other](../../../../UseCases/uc_other.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  11   |   4    |     0      |      9      |    9    |

| Event Type                    | Rules | Models                                                                                                                                                |
| ----------------------------- | ----- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| file-write                    |       |  • <b>A-FW-ProcessName-FileName</b>: File creations for process<br> • <b>A-EPA-UP-TEMP</b>: Processes executed from TEMP directories on this asset    |
| network-connection-successful |       |  • <b>A-NET-OdPort-Outbound</b>: Outbound destination ports per organization<br> • <b>A-NET-HdPort-Outbound</b>: Outbound destination ports per asset |