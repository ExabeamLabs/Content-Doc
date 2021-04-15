Vendor: Palo Alto Networks
==========================
### Product: [GlobalProtect](../ds_palo_alto_networks_globalprotect.md)
### Use-Case: [Abnormal Directory Services Activity](../../../../UseCases/uc_abnormal_directory_services_activity.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   3   |   3    |     1      |      8      |    8    |

| Event Type | Rules                                                                                                                                                                                                                                                                                              | Models                                                                                                                                                                                                                                                   |
| ---------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| vpn-logout | <b>T1098 - Account Manipulation</b><br> ↳ <b>FDS-UCount</b>: Abnormal number of failed directory service events in the user<br> ↳ <b>DS-Count</b>: Abnormal number of directory service events in the organization<br> ↳ <b>DS-UCount</b>: Abnormal number of directory service events in the user |  • <b>DS-UCount</b>: Count of directory service activity events in the user<br> • <b>DS-Count</b>: Count of directory service activity events in the organization<br> • <b>FDS-UCount</b>: Count of failed directory service activity events in the user |