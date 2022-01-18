Vendor: Palo Alto Networks
==========================
### Product: [Palo Alto Aperture](../ds_palo_alto_networks_palo_alto_aperture.md)
### Use-Case: [Data Exfiltration](../../../../UseCases/uc_data_exfiltration.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   3   |   2    |     2      |      6      |    6    |

| Event Type          | Rules                                                                                                                                                                                                                                           | Models                                                                                       |
| ------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| dlp-email-alert-out | <b>T1048 - Exfiltration Over Alternative Protocol</b><br> ↳ <b>EM-OutSpam-M</b>: Email sent to more recipients than usual, at least one external. (M)                                                                                           |  • <b>EM-Recipients-usr</b>: Recipients per Email for user                                   |
| file-write          | <b>T1204 - User Execution</b><br> ↳ <b>FA-TEMP-DIRECTORY-A</b>: Abnormal process has been executed from a temporary directory by this user during file activity<br> ↳ <b>Suspicious-LNK</b>: A suspicious .lnk file used, possible ATP activity |  • <b>FA-UP-TEMP</b>: Process executable TEMP directories for this user during file activity |