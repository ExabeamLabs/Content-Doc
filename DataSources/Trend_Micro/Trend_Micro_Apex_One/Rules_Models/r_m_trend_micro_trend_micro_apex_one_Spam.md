Vendor: Trend Micro
===================
### Product: [Trend Micro Apex One](../ds_trend_micro_trend_micro_apex_one.md)
### Use-Case: [Spam](../../../../UseCases/uc_spam.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   1    |     1      |      5      |    5    |

| Event Type          | Rules                                                                                                                                                                                                                                                                                                               | Models                                                     |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------- |
| dlp-email-alert-out | <b>T1048.003 - Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol</b><br> ↳ <b>EM-OutSpam-M</b>: Email sent to more recipients than usual, at least one external. (M)<br> ↳ <b>EM-OutSpam-L</b>: Email sent to more recipients than usual, at least one external. (L) |  • <b>EM-Recipients-usr</b>: Recipients per Email for user |