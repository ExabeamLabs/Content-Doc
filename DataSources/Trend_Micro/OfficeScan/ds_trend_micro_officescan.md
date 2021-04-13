Vendor: Trend Micro
===================
Product: OfficeScan
-------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  131  |   59   |     19     |      7      |    7    |

|                                  Use-Case                                  | Event Types/Parsers                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | MITRE TTP                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | Content                                                                                                                     |
|:--------------------------------------------------------------------------:| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| [Compromised Credentials](../../../UseCases/uc_compromised_credentials.md) |  dlp-alert<br> ↳ [q-trendmicro-dlp-alert](Parsers/parserContent_q-trendmicro-dlp-alert.md)<br> ↳ [cef-trendmicro-dlp-alert](Parsers/parserContent_cef-trendmicro-dlp-alert.md)<br><br> dlp-email-alert-in<br> ↳ [trendmicro-cef-alert](Parsers/parserContent_trendmicro-cef-alert.md)<br> ↳ [cef-trendmicro-dlp](Parsers/parserContent_cef-trendmicro-dlp.md)<br><br> dlp-email-alert-out<br> ↳ [trendmicro-cef-alert](Parsers/parserContent_trendmicro-cef-alert.md)<br><br> privileged-object-access<br> ↳ [leef-trendmicro-privileged-object-access](Parsers/parserContent_leef-trendmicro-privileged-object-access.md)<br><br> security-alert<br> ↳ [q-trendmicro-syslog-alert](Parsers/parserContent_q-trendmicro-syslog-alert.md)<br> ↳ [s-trendmicro-epp-alert-1](Parsers/parserContent_s-trendmicro-epp-alert-1.md)<br> ↳ [s-trendmicro-epp-alert](Parsers/parserContent_s-trendmicro-epp-alert.md)<br> ↳ [s-trendmicro-epp-alert-2](Parsers/parserContent_s-trendmicro-epp-alert-2.md)<br> ↳ [q-trendmicro-epp-alert](Parsers/parserContent_q-trendmicro-epp-alert.md)<br> ↳ [trendmicro-cef-alert](Parsers/parserContent_trendmicro-cef-alert.md)<br> ↳ [trend-micro-alert-2](Parsers/parserContent_trend-micro-alert-2.md)<br> ↳ [trend-micro-alert-3](Parsers/parserContent_trend-micro-alert-3.md)<br> ↳ [trend-micro-alert-4](Parsers/parserContent_trend-micro-alert-4.md)<br> ↳ [trend-micro-alert-5](Parsers/parserContent_trend-micro-alert-5.md)<br> ↳ [trend-micro-alert-6](Parsers/parserContent_trend-micro-alert-6.md)<br> ↳ [trend-micro-alert-7](Parsers/parserContent_trend-micro-alert-7.md)<br> ↳ [trend-micro-alert-8](Parsers/parserContent_trend-micro-alert-8.md)<br> ↳ [s-trendmicro-security-alert-2](Parsers/parserContent_s-trendmicro-security-alert-2.md)<br> ↳ [s-trendmicro-security-alert-3](Parsers/parserContent_s-trendmicro-security-alert-3.md)<br> ↳ [trend-micro-alert-1](Parsers/parserContent_trend-micro-alert-1.md)<br><br> usb-write<br> ↳ [cef-trendmicro-usb-write](Parsers/parserContent_cef-trendmicro-usb-write.md)<br><br> web-activity-allowed<br> ↳ [trendmicro-cef-web-activity](Parsers/parserContent_trendmicro-cef-web-activity.md)<br> | T1027.005 - Obfuscated Files or Information: Indicator Removal from Tools<br>T1059.001 - Command and Scripting Interperter: PowerShell<br>T1071.001 - Application Layer Protocol: Web Protocols<br>T1078 - Valid Accounts<br>                                                                                                                                                                                                                                                                                                                              | [<ul><li>30 Rules</li></ul><ul><li>18 Models</li></ul>](Rules_Models/r_m_trend_micro_officescan_Compromised_Credentials.md) |
|       [Data Exfiltration](../../../UseCases/uc_data_exfiltration.md)       |  dlp-alert<br> ↳ [q-trendmicro-dlp-alert](Parsers/parserContent_q-trendmicro-dlp-alert.md)<br> ↳ [cef-trendmicro-dlp-alert](Parsers/parserContent_cef-trendmicro-dlp-alert.md)<br><br> dlp-email-alert-in<br> ↳ [trendmicro-cef-alert](Parsers/parserContent_trendmicro-cef-alert.md)<br> ↳ [cef-trendmicro-dlp](Parsers/parserContent_cef-trendmicro-dlp.md)<br><br> dlp-email-alert-out<br> ↳ [trendmicro-cef-alert](Parsers/parserContent_trendmicro-cef-alert.md)<br><br> privileged-object-access<br> ↳ [leef-trendmicro-privileged-object-access](Parsers/parserContent_leef-trendmicro-privileged-object-access.md)<br><br> security-alert<br> ↳ [q-trendmicro-syslog-alert](Parsers/parserContent_q-trendmicro-syslog-alert.md)<br> ↳ [s-trendmicro-epp-alert-1](Parsers/parserContent_s-trendmicro-epp-alert-1.md)<br> ↳ [s-trendmicro-epp-alert](Parsers/parserContent_s-trendmicro-epp-alert.md)<br> ↳ [s-trendmicro-epp-alert-2](Parsers/parserContent_s-trendmicro-epp-alert-2.md)<br> ↳ [q-trendmicro-epp-alert](Parsers/parserContent_q-trendmicro-epp-alert.md)<br> ↳ [trendmicro-cef-alert](Parsers/parserContent_trendmicro-cef-alert.md)<br> ↳ [trend-micro-alert-2](Parsers/parserContent_trend-micro-alert-2.md)<br> ↳ [trend-micro-alert-3](Parsers/parserContent_trend-micro-alert-3.md)<br> ↳ [trend-micro-alert-4](Parsers/parserContent_trend-micro-alert-4.md)<br> ↳ [trend-micro-alert-5](Parsers/parserContent_trend-micro-alert-5.md)<br> ↳ [trend-micro-alert-6](Parsers/parserContent_trend-micro-alert-6.md)<br> ↳ [trend-micro-alert-7](Parsers/parserContent_trend-micro-alert-7.md)<br> ↳ [trend-micro-alert-8](Parsers/parserContent_trend-micro-alert-8.md)<br> ↳ [s-trendmicro-security-alert-2](Parsers/parserContent_s-trendmicro-security-alert-2.md)<br> ↳ [s-trendmicro-security-alert-3](Parsers/parserContent_s-trendmicro-security-alert-3.md)<br> ↳ [trend-micro-alert-1](Parsers/parserContent_trend-micro-alert-1.md)<br><br> usb-write<br> ↳ [cef-trendmicro-usb-write](Parsers/parserContent_cef-trendmicro-usb-write.md)<br><br> web-activity-allowed<br> ↳ [trendmicro-cef-web-activity](Parsers/parserContent_trendmicro-cef-web-activity.md)<br> | T1020 - Automated Exfiltration<br>T1030 - Data Transfer Size Limits<br>T1048 - Exfiltration Over Alternative Protocol<br>T1048.003 - Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol<br>T1052.001 - Exfiltration Over Physical Medium: Exfiltration over USB<br>T1071.001 - Application Layer Protocol: Web Protocols<br>T1204 - User Execution<br>T1567.002 - Exfiltration Over Web Service: Exfiltration to Cloud Storage<br>                                                                           | [<ul><li>55 Rules</li></ul><ul><li>27 Models</li></ul>](Rules_Models/r_m_trend_micro_officescan_Data_Exfiltration.md)       |
|          [Internal Fraud](../../../UseCases/uc_internal_fraud.md)          |  dlp-alert<br> ↳ [q-trendmicro-dlp-alert](Parsers/parserContent_q-trendmicro-dlp-alert.md)<br> ↳ [cef-trendmicro-dlp-alert](Parsers/parserContent_cef-trendmicro-dlp-alert.md)<br><br> dlp-email-alert-in<br> ↳ [trendmicro-cef-alert](Parsers/parserContent_trendmicro-cef-alert.md)<br> ↳ [cef-trendmicro-dlp](Parsers/parserContent_cef-trendmicro-dlp.md)<br><br> dlp-email-alert-out<br> ↳ [trendmicro-cef-alert](Parsers/parserContent_trendmicro-cef-alert.md)<br><br> privileged-object-access<br> ↳ [leef-trendmicro-privileged-object-access](Parsers/parserContent_leef-trendmicro-privileged-object-access.md)<br><br> security-alert<br> ↳ [q-trendmicro-syslog-alert](Parsers/parserContent_q-trendmicro-syslog-alert.md)<br> ↳ [s-trendmicro-epp-alert-1](Parsers/parserContent_s-trendmicro-epp-alert-1.md)<br> ↳ [s-trendmicro-epp-alert](Parsers/parserContent_s-trendmicro-epp-alert.md)<br> ↳ [s-trendmicro-epp-alert-2](Parsers/parserContent_s-trendmicro-epp-alert-2.md)<br> ↳ [q-trendmicro-epp-alert](Parsers/parserContent_q-trendmicro-epp-alert.md)<br> ↳ [trendmicro-cef-alert](Parsers/parserContent_trendmicro-cef-alert.md)<br> ↳ [trend-micro-alert-2](Parsers/parserContent_trend-micro-alert-2.md)<br> ↳ [trend-micro-alert-3](Parsers/parserContent_trend-micro-alert-3.md)<br> ↳ [trend-micro-alert-4](Parsers/parserContent_trend-micro-alert-4.md)<br> ↳ [trend-micro-alert-5](Parsers/parserContent_trend-micro-alert-5.md)<br> ↳ [trend-micro-alert-6](Parsers/parserContent_trend-micro-alert-6.md)<br> ↳ [trend-micro-alert-7](Parsers/parserContent_trend-micro-alert-7.md)<br> ↳ [trend-micro-alert-8](Parsers/parserContent_trend-micro-alert-8.md)<br> ↳ [s-trendmicro-security-alert-2](Parsers/parserContent_s-trendmicro-security-alert-2.md)<br> ↳ [s-trendmicro-security-alert-3](Parsers/parserContent_s-trendmicro-security-alert-3.md)<br> ↳ [trend-micro-alert-1](Parsers/parserContent_trend-micro-alert-1.md)<br><br> usb-write<br> ↳ [cef-trendmicro-usb-write](Parsers/parserContent_cef-trendmicro-usb-write.md)<br><br> web-activity-allowed<br> ↳ [trendmicro-cef-web-activity](Parsers/parserContent_trendmicro-cef-web-activity.md)<br> | T1071.001 - Application Layer Protocol: Web Protocols<br>                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | [<ul><li>3 Rules</li></ul><ul><li>2 Models</li></ul>](Rules_Models/r_m_trend_micro_officescan_Internal_Fraud.md)            |
|        [Lateral Movement](../../../UseCases/uc_lateral_movement.md)        |  dlp-alert<br> ↳ [q-trendmicro-dlp-alert](Parsers/parserContent_q-trendmicro-dlp-alert.md)<br> ↳ [cef-trendmicro-dlp-alert](Parsers/parserContent_cef-trendmicro-dlp-alert.md)<br><br> dlp-email-alert-in<br> ↳ [trendmicro-cef-alert](Parsers/parserContent_trendmicro-cef-alert.md)<br> ↳ [cef-trendmicro-dlp](Parsers/parserContent_cef-trendmicro-dlp.md)<br><br> dlp-email-alert-out<br> ↳ [trendmicro-cef-alert](Parsers/parserContent_trendmicro-cef-alert.md)<br><br> privileged-object-access<br> ↳ [leef-trendmicro-privileged-object-access](Parsers/parserContent_leef-trendmicro-privileged-object-access.md)<br><br> security-alert<br> ↳ [q-trendmicro-syslog-alert](Parsers/parserContent_q-trendmicro-syslog-alert.md)<br> ↳ [s-trendmicro-epp-alert-1](Parsers/parserContent_s-trendmicro-epp-alert-1.md)<br> ↳ [s-trendmicro-epp-alert](Parsers/parserContent_s-trendmicro-epp-alert.md)<br> ↳ [s-trendmicro-epp-alert-2](Parsers/parserContent_s-trendmicro-epp-alert-2.md)<br> ↳ [q-trendmicro-epp-alert](Parsers/parserContent_q-trendmicro-epp-alert.md)<br> ↳ [trendmicro-cef-alert](Parsers/parserContent_trendmicro-cef-alert.md)<br> ↳ [trend-micro-alert-2](Parsers/parserContent_trend-micro-alert-2.md)<br> ↳ [trend-micro-alert-3](Parsers/parserContent_trend-micro-alert-3.md)<br> ↳ [trend-micro-alert-4](Parsers/parserContent_trend-micro-alert-4.md)<br> ↳ [trend-micro-alert-5](Parsers/parserContent_trend-micro-alert-5.md)<br> ↳ [trend-micro-alert-6](Parsers/parserContent_trend-micro-alert-6.md)<br> ↳ [trend-micro-alert-7](Parsers/parserContent_trend-micro-alert-7.md)<br> ↳ [trend-micro-alert-8](Parsers/parserContent_trend-micro-alert-8.md)<br> ↳ [s-trendmicro-security-alert-2](Parsers/parserContent_s-trendmicro-security-alert-2.md)<br> ↳ [s-trendmicro-security-alert-3](Parsers/parserContent_s-trendmicro-security-alert-3.md)<br> ↳ [trend-micro-alert-1](Parsers/parserContent_trend-micro-alert-1.md)<br><br> usb-write<br> ↳ [cef-trendmicro-usb-write](Parsers/parserContent_cef-trendmicro-usb-write.md)<br><br> web-activity-allowed<br> ↳ [trendmicro-cef-web-activity](Parsers/parserContent_trendmicro-cef-web-activity.md)<br> | T1071 - Application Layer Protocol<br>T1071.001 - Application Layer Protocol: Web Protocols<br>                                                                                                                                                                                                                                                                                                                                                                                                                                                            | [<ul><li>4 Rules</li></ul><ul><li>3 Models</li></ul>](Rules_Models/r_m_trend_micro_officescan_Lateral_Movement.md)          |
|       [Malware Detection](../../../UseCases/uc_malware_detection.md)       |  dlp-alert<br> ↳ [q-trendmicro-dlp-alert](Parsers/parserContent_q-trendmicro-dlp-alert.md)<br> ↳ [cef-trendmicro-dlp-alert](Parsers/parserContent_cef-trendmicro-dlp-alert.md)<br><br> dlp-email-alert-in<br> ↳ [trendmicro-cef-alert](Parsers/parserContent_trendmicro-cef-alert.md)<br> ↳ [cef-trendmicro-dlp](Parsers/parserContent_cef-trendmicro-dlp.md)<br><br> dlp-email-alert-out<br> ↳ [trendmicro-cef-alert](Parsers/parserContent_trendmicro-cef-alert.md)<br><br> privileged-object-access<br> ↳ [leef-trendmicro-privileged-object-access](Parsers/parserContent_leef-trendmicro-privileged-object-access.md)<br><br> security-alert<br> ↳ [q-trendmicro-syslog-alert](Parsers/parserContent_q-trendmicro-syslog-alert.md)<br> ↳ [s-trendmicro-epp-alert-1](Parsers/parserContent_s-trendmicro-epp-alert-1.md)<br> ↳ [s-trendmicro-epp-alert](Parsers/parserContent_s-trendmicro-epp-alert.md)<br> ↳ [s-trendmicro-epp-alert-2](Parsers/parserContent_s-trendmicro-epp-alert-2.md)<br> ↳ [q-trendmicro-epp-alert](Parsers/parserContent_q-trendmicro-epp-alert.md)<br> ↳ [trendmicro-cef-alert](Parsers/parserContent_trendmicro-cef-alert.md)<br> ↳ [trend-micro-alert-2](Parsers/parserContent_trend-micro-alert-2.md)<br> ↳ [trend-micro-alert-3](Parsers/parserContent_trend-micro-alert-3.md)<br> ↳ [trend-micro-alert-4](Parsers/parserContent_trend-micro-alert-4.md)<br> ↳ [trend-micro-alert-5](Parsers/parserContent_trend-micro-alert-5.md)<br> ↳ [trend-micro-alert-6](Parsers/parserContent_trend-micro-alert-6.md)<br> ↳ [trend-micro-alert-7](Parsers/parserContent_trend-micro-alert-7.md)<br> ↳ [trend-micro-alert-8](Parsers/parserContent_trend-micro-alert-8.md)<br> ↳ [s-trendmicro-security-alert-2](Parsers/parserContent_s-trendmicro-security-alert-2.md)<br> ↳ [s-trendmicro-security-alert-3](Parsers/parserContent_s-trendmicro-security-alert-3.md)<br> ↳ [trend-micro-alert-1](Parsers/parserContent_trend-micro-alert-1.md)<br><br> usb-write<br> ↳ [cef-trendmicro-usb-write](Parsers/parserContent_cef-trendmicro-usb-write.md)<br><br> web-activity-allowed<br> ↳ [trendmicro-cef-web-activity](Parsers/parserContent_trendmicro-cef-web-activity.md)<br> | T1027.005 - Obfuscated Files or Information: Indicator Removal from Tools<br>T1059.001 - Command and Scripting Interperter: PowerShell<br>T1071 - Application Layer Protocol<br>T1071.001 - Application Layer Protocol: Web Protocols<br>T1078 - Valid Accounts<br>T1090.003 - Proxy: Multi-hop Proxy<br>T1102 - Web Service<br>T1204 - User Execution<br>T1496 - Resource Hijacking<br>T1550.002 - Use Alternate Authentication Material: Pass the Hash<br>T1568 - Dynamic Resolution<br>T1568.002 - Dynamic Resolution: Domain Generation Algorithms<br> | [<ul><li>45 Rules</li></ul><ul><li>13 Models</li></ul>](Rules_Models/r_m_trend_micro_officescan_Malware_Detection.md)       |
|                [Phishing](../../../UseCases/uc_phishing.md)                |  dlp-alert<br> ↳ [q-trendmicro-dlp-alert](Parsers/parserContent_q-trendmicro-dlp-alert.md)<br> ↳ [cef-trendmicro-dlp-alert](Parsers/parserContent_cef-trendmicro-dlp-alert.md)<br><br> dlp-email-alert-in<br> ↳ [trendmicro-cef-alert](Parsers/parserContent_trendmicro-cef-alert.md)<br> ↳ [cef-trendmicro-dlp](Parsers/parserContent_cef-trendmicro-dlp.md)<br><br> dlp-email-alert-out<br> ↳ [trendmicro-cef-alert](Parsers/parserContent_trendmicro-cef-alert.md)<br><br> privileged-object-access<br> ↳ [leef-trendmicro-privileged-object-access](Parsers/parserContent_leef-trendmicro-privileged-object-access.md)<br><br> security-alert<br> ↳ [q-trendmicro-syslog-alert](Parsers/parserContent_q-trendmicro-syslog-alert.md)<br> ↳ [s-trendmicro-epp-alert-1](Parsers/parserContent_s-trendmicro-epp-alert-1.md)<br> ↳ [s-trendmicro-epp-alert](Parsers/parserContent_s-trendmicro-epp-alert.md)<br> ↳ [s-trendmicro-epp-alert-2](Parsers/parserContent_s-trendmicro-epp-alert-2.md)<br> ↳ [q-trendmicro-epp-alert](Parsers/parserContent_q-trendmicro-epp-alert.md)<br> ↳ [trendmicro-cef-alert](Parsers/parserContent_trendmicro-cef-alert.md)<br> ↳ [trend-micro-alert-2](Parsers/parserContent_trend-micro-alert-2.md)<br> ↳ [trend-micro-alert-3](Parsers/parserContent_trend-micro-alert-3.md)<br> ↳ [trend-micro-alert-4](Parsers/parserContent_trend-micro-alert-4.md)<br> ↳ [trend-micro-alert-5](Parsers/parserContent_trend-micro-alert-5.md)<br> ↳ [trend-micro-alert-6](Parsers/parserContent_trend-micro-alert-6.md)<br> ↳ [trend-micro-alert-7](Parsers/parserContent_trend-micro-alert-7.md)<br> ↳ [trend-micro-alert-8](Parsers/parserContent_trend-micro-alert-8.md)<br> ↳ [s-trendmicro-security-alert-2](Parsers/parserContent_s-trendmicro-security-alert-2.md)<br> ↳ [s-trendmicro-security-alert-3](Parsers/parserContent_s-trendmicro-security-alert-3.md)<br> ↳ [trend-micro-alert-1](Parsers/parserContent_trend-micro-alert-1.md)<br><br> usb-write<br> ↳ [cef-trendmicro-usb-write](Parsers/parserContent_cef-trendmicro-usb-write.md)<br><br> web-activity-allowed<br> ↳ [trendmicro-cef-web-activity](Parsers/parserContent_trendmicro-cef-web-activity.md)<br> | T1048 - Exfiltration Over Alternative Protocol<br>T1048.003 - Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol<br>T1071.001 - Application Layer Protocol: Web Protocols<br>T1566.002 - Phishing: Spearphishing Link<br>T1568 - Dynamic Resolution<br>                                                                                                                                                                                                                                                      | [<ul><li>14 Rules</li></ul><ul><li>4 Models</li></ul>](Rules_Models/r_m_trend_micro_officescan_Phishing.md)                 |
|     [Privileged Activity](../../../UseCases/uc_privileged_activity.md)     |  dlp-alert<br> ↳ [q-trendmicro-dlp-alert](Parsers/parserContent_q-trendmicro-dlp-alert.md)<br> ↳ [cef-trendmicro-dlp-alert](Parsers/parserContent_cef-trendmicro-dlp-alert.md)<br><br> dlp-email-alert-in<br> ↳ [trendmicro-cef-alert](Parsers/parserContent_trendmicro-cef-alert.md)<br> ↳ [cef-trendmicro-dlp](Parsers/parserContent_cef-trendmicro-dlp.md)<br><br> dlp-email-alert-out<br> ↳ [trendmicro-cef-alert](Parsers/parserContent_trendmicro-cef-alert.md)<br><br> privileged-object-access<br> ↳ [leef-trendmicro-privileged-object-access](Parsers/parserContent_leef-trendmicro-privileged-object-access.md)<br><br> security-alert<br> ↳ [q-trendmicro-syslog-alert](Parsers/parserContent_q-trendmicro-syslog-alert.md)<br> ↳ [s-trendmicro-epp-alert-1](Parsers/parserContent_s-trendmicro-epp-alert-1.md)<br> ↳ [s-trendmicro-epp-alert](Parsers/parserContent_s-trendmicro-epp-alert.md)<br> ↳ [s-trendmicro-epp-alert-2](Parsers/parserContent_s-trendmicro-epp-alert-2.md)<br> ↳ [q-trendmicro-epp-alert](Parsers/parserContent_q-trendmicro-epp-alert.md)<br> ↳ [trendmicro-cef-alert](Parsers/parserContent_trendmicro-cef-alert.md)<br> ↳ [trend-micro-alert-2](Parsers/parserContent_trend-micro-alert-2.md)<br> ↳ [trend-micro-alert-3](Parsers/parserContent_trend-micro-alert-3.md)<br> ↳ [trend-micro-alert-4](Parsers/parserContent_trend-micro-alert-4.md)<br> ↳ [trend-micro-alert-5](Parsers/parserContent_trend-micro-alert-5.md)<br> ↳ [trend-micro-alert-6](Parsers/parserContent_trend-micro-alert-6.md)<br> ↳ [trend-micro-alert-7](Parsers/parserContent_trend-micro-alert-7.md)<br> ↳ [trend-micro-alert-8](Parsers/parserContent_trend-micro-alert-8.md)<br> ↳ [s-trendmicro-security-alert-2](Parsers/parserContent_s-trendmicro-security-alert-2.md)<br> ↳ [s-trendmicro-security-alert-3](Parsers/parserContent_s-trendmicro-security-alert-3.md)<br> ↳ [trend-micro-alert-1](Parsers/parserContent_trend-micro-alert-1.md)<br><br> usb-write<br> ↳ [cef-trendmicro-usb-write](Parsers/parserContent_cef-trendmicro-usb-write.md)<br><br> web-activity-allowed<br> ↳ [trendmicro-cef-web-activity](Parsers/parserContent_trendmicro-cef-web-activity.md)<br> | T1068 - Exploitation for Privilege Escalation<br>                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          | [<ul><li>1 Rules</li></ul>](Rules_Models/r_m_trend_micro_officescan_Privileged_Activity.md)                                 |
|    [Ransomware Detection](../../../UseCases/uc_ransomware_detection.md)    |  dlp-alert<br> ↳ [q-trendmicro-dlp-alert](Parsers/parserContent_q-trendmicro-dlp-alert.md)<br> ↳ [cef-trendmicro-dlp-alert](Parsers/parserContent_cef-trendmicro-dlp-alert.md)<br><br> dlp-email-alert-in<br> ↳ [trendmicro-cef-alert](Parsers/parserContent_trendmicro-cef-alert.md)<br> ↳ [cef-trendmicro-dlp](Parsers/parserContent_cef-trendmicro-dlp.md)<br><br> dlp-email-alert-out<br> ↳ [trendmicro-cef-alert](Parsers/parserContent_trendmicro-cef-alert.md)<br><br> privileged-object-access<br> ↳ [leef-trendmicro-privileged-object-access](Parsers/parserContent_leef-trendmicro-privileged-object-access.md)<br><br> security-alert<br> ↳ [q-trendmicro-syslog-alert](Parsers/parserContent_q-trendmicro-syslog-alert.md)<br> ↳ [s-trendmicro-epp-alert-1](Parsers/parserContent_s-trendmicro-epp-alert-1.md)<br> ↳ [s-trendmicro-epp-alert](Parsers/parserContent_s-trendmicro-epp-alert.md)<br> ↳ [s-trendmicro-epp-alert-2](Parsers/parserContent_s-trendmicro-epp-alert-2.md)<br> ↳ [q-trendmicro-epp-alert](Parsers/parserContent_q-trendmicro-epp-alert.md)<br> ↳ [trendmicro-cef-alert](Parsers/parserContent_trendmicro-cef-alert.md)<br> ↳ [trend-micro-alert-2](Parsers/parserContent_trend-micro-alert-2.md)<br> ↳ [trend-micro-alert-3](Parsers/parserContent_trend-micro-alert-3.md)<br> ↳ [trend-micro-alert-4](Parsers/parserContent_trend-micro-alert-4.md)<br> ↳ [trend-micro-alert-5](Parsers/parserContent_trend-micro-alert-5.md)<br> ↳ [trend-micro-alert-6](Parsers/parserContent_trend-micro-alert-6.md)<br> ↳ [trend-micro-alert-7](Parsers/parserContent_trend-micro-alert-7.md)<br> ↳ [trend-micro-alert-8](Parsers/parserContent_trend-micro-alert-8.md)<br> ↳ [s-trendmicro-security-alert-2](Parsers/parserContent_s-trendmicro-security-alert-2.md)<br> ↳ [s-trendmicro-security-alert-3](Parsers/parserContent_s-trendmicro-security-alert-3.md)<br> ↳ [trend-micro-alert-1](Parsers/parserContent_trend-micro-alert-1.md)<br><br> usb-write<br> ↳ [cef-trendmicro-usb-write](Parsers/parserContent_cef-trendmicro-usb-write.md)<br><br> web-activity-allowed<br> ↳ [trendmicro-cef-web-activity](Parsers/parserContent_trendmicro-cef-web-activity.md)<br> | T1027.005 - Obfuscated Files or Information: Indicator Removal from Tools<br>T1059.001 - Command and Scripting Interperter: PowerShell<br>T1071 - Application Layer Protocol<br>T1071.001 - Application Layer Protocol: Web Protocols<br>T1078 - Valid Accounts<br>T1090.003 - Proxy: Multi-hop Proxy<br>T1102 - Web Service<br>T1204 - User Execution<br>T1496 - Resource Hijacking<br>T1550.002 - Use Alternate Authentication Material: Pass the Hash<br>T1568 - Dynamic Resolution<br>T1568.002 - Dynamic Resolution: Domain Generation Algorithms<br> | [<ul><li>42 Rules</li></ul><ul><li>12 Models</li></ul>](Rules_Models/r_m_trend_micro_officescan_Ransomware_Detection.md)    |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                                                                                                                                                                        | Execution                                                                                                                                                                                                                                                       | Persistence                                                         | Privilege Escalation                                                                                                                                          | Defense Evasion                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | Credential Access | Discovery | Lateral Movement                                                                           | Collection | Command and Control                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | Exfiltration                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | Impact                                                                  |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------- | --------- | ------------------------------------------------------------------------------------------ | ---------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------- |
| [Phishing: Spearphishing Link](https://attack.mitre.org/techniques/T1566/002)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Phishing](https://attack.mitre.org/techniques/T1566)<br><br> | [Command and Scripting Interperter](https://attack.mitre.org/techniques/T1059)<br><br>[User Execution](https://attack.mitre.org/techniques/T1204)<br><br>[Command and Scripting Interperter: PowerShell](https://attack.mitre.org/techniques/T1059/001)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068)<br><br> | [Obfuscated Files or Information: Indicator Removal from Tools](https://attack.mitre.org/techniques/T1027/005)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550)<br><br>[Use Alternate Authentication Material: Pass the Hash](https://attack.mitre.org/techniques/T1550/002)<br><br>[Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027)<br><br> |                   |           | [Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550)<br><br> |            | [Web Service](https://attack.mitre.org/techniques/T1102)<br><br>[Application Layer Protocol: Web Protocols](https://attack.mitre.org/techniques/T1071/001)<br><br>[Dynamic Resolution](https://attack.mitre.org/techniques/T1568)<br><br>[Dynamic Resolution: Domain Generation Algorithms](https://attack.mitre.org/techniques/T1568/002)<br><br>[Proxy: Multi-hop Proxy](https://attack.mitre.org/techniques/T1090/003)<br><br>[Application Layer Protocol](https://attack.mitre.org/techniques/T1071)<br><br>[Proxy](https://attack.mitre.org/techniques/T1090)<br><br> | [Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048)<br><br>[Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol](https://attack.mitre.org/techniques/T1048/003)<br><br>[Exfiltration Over Physical Medium: Exfiltration over USB](https://attack.mitre.org/techniques/T1052/001)<br><br>[Data Transfer Size Limits](https://attack.mitre.org/techniques/T1030)<br><br>[Exfiltration Over Physical Medium](https://attack.mitre.org/techniques/T1052)<br><br>[Automated Exfiltration](https://attack.mitre.org/techniques/T1020)<br><br>[Exfiltration Over Web Service: Exfiltration to Cloud Storage](https://attack.mitre.org/techniques/T1567/002)<br><br>[Exfiltration Over Web Service](https://attack.mitre.org/techniques/T1567)<br><br> | [Resource Hijacking](https://attack.mitre.org/techniques/T1496)<br><br> |