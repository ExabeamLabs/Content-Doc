Vendor: Sensormatik
===================
### Product: [Sensormatik](../ds_sensormatik_sensormatik.md)
### Use-Case: [Data Exfiltration](../../../../UseCases/uc_data_exfiltration.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   1   |   1    |     1      |      2      |    2    |

| Event Type          | Rules                                                                                                                                                 | Models                                                     |
| ------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------- |
| dlp-email-alert-out | <b>T1048 - Exfiltration Over Alternative Protocol</b><br> ↳ <b>EM-OutSpam-M</b>: Email sent to more recipients than usual, at least one external. (M) |  • <b>EM-Recipients-usr</b>: Recipients per Email for user |