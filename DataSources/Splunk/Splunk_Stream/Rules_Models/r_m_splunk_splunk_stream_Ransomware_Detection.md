Vendor: Splunk
==============
### Product: [Splunk Stream](../ds_splunk_splunk_stream.md)
### Use-Case: [Ransomware Detection](../../../../UseCases/uc_ransomware_detection.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   4   |   0    |     2      |      3      |    3    |

| Event Type   | Rules                                                                                                                                                                                                                                                                                                                         | Models |
| ------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| dns-query    | <b>T1071.004 - Application Layer Protocol: DNS</b><br> ↳ <b>A-DNS-MALDOM-QUERY</b>: DNS query for blacklisted domain from this asset<br><br><b>T1568.002 - Dynamic Resolution: Domain Generation Algorithms</b><br> ↳ <b>A-DNS-DGADOM-QUERY</b>: DNS query for DGA domain from this asset                                     |        |
| dns-response | <b>T1071.004 - Application Layer Protocol: DNS</b><br> ↳ <b>A-DNS-MALDOM-RESPONSE</b>: DNS query for blacklisted domain was successful from this asset<br><br><b>T1568.002 - Dynamic Resolution: Domain Generation Algorithms</b><br> ↳ <b>A-DNS-DGADOM-RESPONSE</b>: DNS query for DGA domain was successful from this asset |        |