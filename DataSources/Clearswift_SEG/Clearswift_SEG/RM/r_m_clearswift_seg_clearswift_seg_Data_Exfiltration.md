Vendor: Clearswift SEG
======================
### Product: [Clearswift SEG](../ds_clearswift_seg_clearswift_seg.md)
### Use-Case: [Data Exfiltration](../../../../UseCases/uc_data_exfiltration.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   1   |   1    |     1      |      4      |    4    |

| Event Type          | Rules                                                                                                                                                 | Models                                                     |
| ------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------- |
| dlp-email-alert-out | <b>T1048 - Exfiltration Over Alternative Protocol</b><br> ↳ <b>EM-OutSpam-M</b>: Email sent to more recipients than usual, at least one external. (M) |  • <b>EM-Recipients-usr</b>: Recipients per Email for user |