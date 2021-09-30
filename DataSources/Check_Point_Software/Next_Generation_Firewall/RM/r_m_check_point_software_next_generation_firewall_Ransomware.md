Vendor: Check Point Software
============================
### Product: [Next Generation Firewall](../ds_check_point_software_next_generation_firewall.md)
### Use-Case: [Ransomware](../../../../UseCases/uc_ransomware.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   0    |     1      |      2      |    2    |

| Event Type                    | Rules                                                                                                                                                     | Models |
| ----------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| network-connection-failed     | <b>T1071 - Application Layer Protocol</b><br> ↳ <b>A-NETF-Ransomware-IP</b>: Asset failed to connect to an IP address which is associated to Ransomware   |        |
| network-connection-successful | <b>T1071 - Application Layer Protocol</b><br> ↳ <b>A-NET-Ransomware-IP</b>: Asset attempted to connect to an IP address which is associated to Ransomware |        |