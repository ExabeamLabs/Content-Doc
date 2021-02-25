Vendor: Citrix
==============
### Product: [Citrix XenDesktop](../ds_citrix_citrix_xendesktop.md)
### Use-Case: [Other](../../../../UseCases/uc_other.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   3   |   2    |     1      |      1      |    1    |

| Event Type   | Rules                                                                                                                                                                                                                                                                                        | Models                                                                                                                                              |
| ------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| remote-logon | <br> ↳ <b>KL-USn-A</b>: Abnormal service to obtain TGTs for user<br><br><b>T1550 - Use Alternate Authentication Material</b><br> ↳ <b>RLA-UAPackage-F</b>: First time usage of Windows authentication package<br> ↳ <b>RLA-UAPackage-A</b>: Abnormal usage of Windows authentication package |  • <b>RLA-UAPackage</b>: Windows authentication packages used when connecting to remote hosts<br> • <b>KL-USn</b>: Services to obtain TGTs for user |