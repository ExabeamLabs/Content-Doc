Vendor: F5
==========
### Product: [F5 BIG-IP Advanced Firewall Module (AFM)](../ds_f5_f5_big-ip_advanced_firewall_module_(afm).md)
### Use-Case: [Compromised Credentials](../../../../UseCases/uc_compromised_credentials.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   1   |   1    |     1      |      2      |    2    |

| Event Type                    | Rules                                                                                                                              | Models                                                                                                  |
| ----------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| network-connection-successful | <b>T1046 - Network Service Scanning</b><br> ↳ <b>NETFLOW-OsH-SweepScan-A</b>: Abnormal for asset to access 20 assets in 10 seconds |  • <b>A-NETFLOW-OsH-Scanners</b>: Assets that access multiple assets within seconds in the organization |