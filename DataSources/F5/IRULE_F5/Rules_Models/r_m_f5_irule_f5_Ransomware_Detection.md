Vendor: F5
==========
### Product: [IRULE F5](../ds_f5_irule_f5.md)
### Use-Case: [Ransomware Detection](../../../../UseCases/uc_ransomware_detection.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   3   |   1    |     1      |      1      |    1    |

| Event Type                    | Rules                                                                                                                                                                                                                                                          | Models                                                                                    |
| ----------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| network-connection-successful | <b>T1071 - Application Layer Protocol</b><br> ↳ <b>NET-TI-H-Outbound</b>: Outbound connection to a known malicious host<br> ↳ <b>NET-OdZ-Inbound-F</b>: First inbound connection to zone.<br> ↳ <b>NET-OdZ-Inbound-A</b>: Abnormal inbound connection to zone. |  • <b>A-NET-OdZ-Inbound</b>: Network zones with inbound communication in the organization |