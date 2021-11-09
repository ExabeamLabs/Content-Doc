Vendor: Splunk
==============
Product: Splunk Stream
----------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  35   |   20   |     4      |      2      |    2    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Data Exfiltration](../../../UseCases/uc_data_exfiltration.md) |  dlp-alert<br> ↳[s-stream-dhcp](Ps/pC_sstreamdhcp.md)<br><br> dns-response<br> ↳[s-splunkstream-dns-response](Ps/pC_ssplunkstreamdnsresponse.md)<br> ↳[s-splunkstream-dns-query](Ps/pC_ssplunkstreamdnsquery.md)<br> | T1020 - Automated Exfiltration<br>T1048 - Exfiltration Over Alternative Protocol<br>T1071 - Application Layer Protocol<br>T1204 - User Execution<br> | [<ul><li>29 Rules</li></ul><ul><li>18 Models</li></ul>](RM/r_m_splunk_splunk_stream_Data_Exfiltration.md) |
|         [Data Leak](../../../UseCases/uc_data_leak.md)         |  dlp-alert<br> ↳[s-stream-dhcp](Ps/pC_sstreamdhcp.md)<br><br> dns-response<br> ↳[s-splunkstream-dns-response](Ps/pC_ssplunkstreamdnsresponse.md)<br> ↳[s-splunkstream-dns-query](Ps/pC_ssplunkstreamdnsquery.md)<br> | T1020 - Automated Exfiltration<br>T1048 - Exfiltration Over Alternative Protocol<br>T1071 - Application Layer Protocol<br>T1204 - User Execution<br> | [<ul><li>29 Rules</li></ul><ul><li>18 Models</li></ul>](RM/r_m_splunk_splunk_stream_Data_Leak.md)         |
|    [Malware](../../../UseCases/uc_malware.md)    |  dlp-alert<br> ↳[s-stream-dhcp](Ps/pC_sstreamdhcp.md)<br><br> dns-response<br> ↳[s-splunkstream-dns-response](Ps/pC_ssplunkstreamdnsresponse.md)<br> ↳[s-splunkstream-dns-query](Ps/pC_ssplunkstreamdnsquery.md)<br> | T1204 - User Execution<br>    | [<ul><li>2 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_splunk_splunk_stream_Malware.md)    |
|    [Other](../../../UseCases/uc_other.md)    |  dlp-alert<br> ↳[s-stream-dhcp](Ps/pC_sstreamdhcp.md)<br><br> dns-response<br> ↳[s-splunkstream-dns-response](Ps/pC_ssplunkstreamdnsresponse.md)<br> ↳[s-splunkstream-dns-query](Ps/pC_ssplunkstreamdnsquery.md)<br> |    | [<ul><li>4 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_splunk_splunk_stream_Other.md)    |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access | Execution                                                           | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection | Command and Control                                                             | Exfiltration                                                                                                                                                           | Impact |
| -------------- | ------------------------------------------------------------------- | ----------- | -------------------- | --------------- | ----------------- | --------- | ---------------- | ---------- | ------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
|                | [User Execution](https://attack.mitre.org/techniques/T1204)<br><br> |             |                      |                 |                   |           |                  |            | [Application Layer Protocol](https://attack.mitre.org/techniques/T1071)<br><br> | [Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048)<br><br>[Automated Exfiltration](https://attack.mitre.org/techniques/T1020)<br><br> |        |