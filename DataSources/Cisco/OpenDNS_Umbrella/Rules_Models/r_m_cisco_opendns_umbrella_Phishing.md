Vendor: Cisco
=============
### Product: [OpenDNS Umbrella](../ds_cisco_opendns_umbrella.md)
### Use-Case: [Phishing](../../../../UseCases/uc_phishing.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   6   |   1    |     2      |      6      |    6    |

| Event Type                    | Rules                                                                                                                                                                                                                                                      | Models                                                |
| ----------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------- |
| dns-query                     | <b>T1048 - Exfiltration Over Alternative Protocol</b><b>T1071 - Application Layer Protocol</b><br> ↳ <b>A-DNS-MALDOM-QUERY</b>: DNS query for blacklisted domain from this asset<br> ↳ <b>A-DNS-DGADOM-QUERY</b>: DNS query for DGA domain from this asset |                                                       |
| dns-response                  | <b>T1071 - Application Layer Protocol</b><br> ↳ <b>A-DNS-MALDOM-RESPONSE</b>: DNS query for blacklisted domain was successful from this asset                                                                                                              |                                                       |
| network-connection-failed     | <b>T1071 - Application Layer Protocol</b><br> ↳ <b>NETF-TI-IP-Outbound</b>: Outbound failed connection to a known malicious IP                                                                                                                             |                                                       |
| network-connection-successful | <b>T1071 - Application Layer Protocol</b><br> ↳ <b>NET-TI-H-Outbound</b>: Outbound connection to a known malicious host                                                                                                                                    |                                                       |
| vpn-logout                    | <b>T1048 - Exfiltration Over Alternative Protocol</b><br> ↳ <b>EM-BSum-in</b>: Abnormal size of incoming emails                                                                                                                                            |  • <b>EM-BSum-in</b>: Sum of bytes in incoming emails |