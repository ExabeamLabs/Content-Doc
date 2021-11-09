Vendor: Amazon
==============
### Product: [AWS CloudTrail](../ds_amazon_aws_cloudtrail.md)
### Use-Case: [Evasion](../../../../UseCases/uc_evasion.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   3   |   0    |     1      |      9      |    9    |

| Event Type         | Rules                                                                                                                                                                                   | Models |
| ------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| app-activity       | <b>T1090.003 - Proxy: Multi-hop Proxy</b><br> ↳ <b>Auth-Tor-Shost</b>: User authentication or login from a known TOR IP                                                                 |        |
| app-login          | <b>T1090.003 - Proxy: Multi-hop Proxy</b><br> ↳ <b>Auth-Tor-Shost</b>: User authentication or login from a known TOR IP                                                                 |        |
| netflow-connection | <b>T1090.003 - Proxy: Multi-hop Proxy</b><br> ↳ <b>A-NET-TOR-Outbound</b>: Outbound connection to a known TOR IP<br> ↳ <b>A-NET-TOR-Inbound</b>: Inbound connection from a known TOR IP |        |