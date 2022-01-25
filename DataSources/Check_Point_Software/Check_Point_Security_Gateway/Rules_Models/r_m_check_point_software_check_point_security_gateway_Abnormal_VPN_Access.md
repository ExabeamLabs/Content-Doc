Vendor: Check Point Software
============================
### Product: [Check Point Security Gateway](../ds_check_point_software_check_point_security_gateway.md)
### Use-Case: [Abnormal VPN Access](../../../../UseCases/uc_abnormal_vpn_access.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   1    |     1      |      2      |    2    |

| Event Type       | Rules                                                                                                           | Models                                              |
| ---------------- | --------------------------------------------------------------------------------------------------------------- | --------------------------------------------------- |
| failed-vpn-login | <b>T1133 - External Remote Services</b><br> ↳ <b>SEQ-UH-15</b>: Failed VPN login                                |                                                     |
| vpn-login        | <b>T1133 - External Remote Services</b><br> ↳ <b>VPN-GsH-F</b>: First VPN connection from device for peer group |  • <b>VPN-GsH</b>: VPN endpoints in this peer group |