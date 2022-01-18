Vendor: Barracuda
=================
### Product: [Barracuda Email Security Gateway](../ds_barracuda_barracuda_email_security_gateway.md)
### Use-Case: [Data Exfiltration](../../../../UseCases/uc_data_exfiltration.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   1   |   1    |     1      |      5      |    5    |

| Event Type          | Rules                                                                                                                                                 | Models                                                     |
| ------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------- |
| dlp-email-alert-out | <b>T1048 - Exfiltration Over Alternative Protocol</b><br> ↳ <b>EM-OutSpam-M</b>: Email sent to more recipients than usual, at least one external. (M) |  • <b>EM-Recipients-usr</b>: Recipients per Email for user |