Vendor: Splunk
==============
Product: Splunk Stream
----------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  35   |   20   |     5      |      2      |    2    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Data Exfiltration](../../../UseCases/uc_data_exfiltration.md) |  dlp-alert<br> ↳[s-stream-dhcp](Ps/pC_sstreamdhcp.md)<br><br> dns-response<br> ↳[s-splunkstream-dns-response](Ps/pC_ssplunkstreamdnsresponse.md)<br> ↳[s-splunkstream-dns-query](Ps/pC_ssplunkstreamdnsquery.md)<br> | T1020 - Automated Exfiltration<br>T1071 - Application Layer Protocol<br>TA0010 - TA0010<br>    | [<ul><li>29 Rules</li></ul><ul><li>18 Models</li></ul>](RM/r_m_splunk_splunk_stream_Data_Exfiltration.md) |
|         [Data Leak](../../../UseCases/uc_data_leak.md)         |  dlp-alert<br> ↳[s-stream-dhcp](Ps/pC_sstreamdhcp.md)<br><br> dns-response<br> ↳[s-splunkstream-dns-response](Ps/pC_ssplunkstreamdnsresponse.md)<br> ↳[s-splunkstream-dns-query](Ps/pC_ssplunkstreamdnsquery.md)<br> | T1020 - Automated Exfiltration<br>T1071 - Application Layer Protocol<br>TA0010 - TA0010<br>    | [<ul><li>29 Rules</li></ul><ul><li>18 Models</li></ul>](RM/r_m_splunk_splunk_stream_Data_Leak.md)         |
|    [Malware](../../../UseCases/uc_malware.md)    |  dlp-alert<br> ↳[s-stream-dhcp](Ps/pC_sstreamdhcp.md)<br><br> dns-response<br> ↳[s-splunkstream-dns-response](Ps/pC_ssplunkstreamdnsresponse.md)<br> ↳[s-splunkstream-dns-query](Ps/pC_ssplunkstreamdnsquery.md)<br> | T1071 - Application Layer Protocol<br>T1568.002 - Dynamic Resolution: Domain Generation Algorithms<br>TA0002 - TA0002<br> | [<ul><li>6 Rules</li></ul><ul><li>2 Models</li></ul>](RM/r_m_splunk_splunk_stream_Malware.md)    |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection | Command and Control                                                                                                                                                                                                                                             | Exfiltration                                                                | Impact |
| -------------- | --------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | ---------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------- | ------ |
|                |           |             |                      |                 |                   |           |                  |            | [Dynamic Resolution](https://attack.mitre.org/techniques/T1568)<br><br>[Dynamic Resolution: Domain Generation Algorithms](https://attack.mitre.org/techniques/T1568/002)<br><br>[Application Layer Protocol](https://attack.mitre.org/techniques/T1071)<br><br> | [Automated Exfiltration](https://attack.mitre.org/techniques/T1020)<br><br> |        |