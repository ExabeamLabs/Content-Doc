Vendor: Microsoft
=================
### Product: [Microsoft Windows](../ds_microsoft_microsoft_windows.md)
### Use-Case: [Phishing](../../../../UseCases/uc_phishing.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   5   |   1    |     3      |     54      |   54    |

| Event Type                    | Rules                                                                                                                                                                                                                                                                                     | Models |
| ----------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| dns-query                     | <b>T1071.004 - Application Layer Protocol: DNS</b><br> ↳ <b>A-DNS-MALDOM-QUERY</b>: DNS query for blacklisted domain from this asset<br><br><b>T1568.002 - Dynamic Resolution: Domain Generation Algorithms</b><br> ↳ <b>A-DNS-DGADOM-QUERY</b>: DNS query for DGA domain from this asset |        |
| dns-response                  | <b>T1071.004 - Application Layer Protocol: DNS</b><br> ↳ <b>A-DNS-MALDOM-RESPONSE</b>: DNS query for blacklisted domain was successful from this asset                                                                                                                                    |        |
| network-connection-successful | <b>T1071 - Application Layer Protocol</b><br> ↳ <b>NET-TI-H-Outbound</b>: Outbound connection to a known malicious host                                                                                                                                                                   |        |
| process-network               | <b>T1071 - Application Layer Protocol</b><br> ↳ <b>NET-TI-H-Outbound</b>: Outbound connection to a known malicious host                                                                                                                                                                   |        |
| process-network-failed        | <b>T1071 - Application Layer Protocol</b><br> ↳ <b>NETF-TI-IP-Outbound</b>: Outbound failed connection to a known malicious IP                                                                                                                                                            |        |