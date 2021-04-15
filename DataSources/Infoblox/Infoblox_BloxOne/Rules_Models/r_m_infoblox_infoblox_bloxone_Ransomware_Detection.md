Vendor: Infoblox
================
### Product: [Infoblox BloxOne](../ds_infoblox_infoblox_bloxone.md)
### Use-Case: [Ransomware Detection](../../../../UseCases/uc_ransomware_detection.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   0    |     2      |      1      |    1    |

| Event Type   | Rules                                                                                                                                                                                                                                                                                                                         | Models |
| ------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| dns-response | <b>T1071.004 - Application Layer Protocol: DNS</b><br> ↳ <b>A-DNS-MALDOM-RESPONSE</b>: DNS query for blacklisted domain was successful from this asset<br><br><b>T1568.002 - Dynamic Resolution: Domain Generation Algorithms</b><br> ↳ <b>A-DNS-DGADOM-RESPONSE</b>: DNS query for DGA domain was successful from this asset |        |