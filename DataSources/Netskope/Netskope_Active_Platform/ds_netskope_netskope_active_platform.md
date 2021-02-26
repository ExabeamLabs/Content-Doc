Vendor: Netskope
================
Product: Netskope Active Platform
---------------------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  178  |   84   |     16     |     12      |   12    |

|                                  Use-Case                                  | Event Types/Parsers                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | MITRE TTP                                                                                                                                                                                                                         | Content                                                                                                                                |
|:--------------------------------------------------------------------------:| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| [Compromised Credentials](../../../UseCases/uc_compromised_credentials.md) |  app-activity<br> ↳ [netskope-activity](Parsers/parserContent_netskope-activity.md)<br> ↳ [s-netskope-activity](Parsers/parserContent_s-netskope-activity.md)<br><br> app-login<br> ↳ [netskope-login](Parsers/parserContent_netskope-login.md)<br> ↳ [s-netskope-login](Parsers/parserContent_s-netskope-login.md)<br><br> dlp-alert<br> ↳ [cef-netskope-dlp-alert](Parsers/parserContent_cef-netskope-dlp-alert.md)<br> ↳ [cef-netskope-dlp-alert-1](Parsers/parserContent_cef-netskope-dlp-alert-1.md)<br> ↳ [netscope-dlp-alert-activity](Parsers/parserContent_netscope-dlp-alert-activity.md)<br> ↳ [netskope-dlp-alert](Parsers/parserContent_netskope-dlp-alert.md)<br><br> dlp-email-alert-out<br> ↳ [cef-netskope-dlp-email-alert-1](Parsers/parserContent_cef-netskope-dlp-email-alert-1.md)<br><br> file-delete<br> ↳ [netskope-activity](Parsers/parserContent_netskope-activity.md)<br> ↳ [s-netskope-activity](Parsers/parserContent_s-netskope-activity.md)<br><br> file-download<br> ↳ [netskope-activity](Parsers/parserContent_netskope-activity.md)<br> ↳ [s-netskope-activity](Parsers/parserContent_s-netskope-activity.md)<br><br> file-permission-change<br> ↳ [netskope-activity](Parsers/parserContent_netskope-activity.md)<br> ↳ [s-netskope-activity](Parsers/parserContent_s-netskope-activity.md)<br><br> file-read<br> ↳ [netskope-activity](Parsers/parserContent_netskope-activity.md)<br> ↳ [s-netskope-activity](Parsers/parserContent_s-netskope-activity.md)<br><br> file-upload<br> ↳ [netskope-activity](Parsers/parserContent_netskope-activity.md)<br> ↳ [s-netskope-activity](Parsers/parserContent_s-netskope-activity.md)<br><br> file-write<br> ↳ [netskope-activity](Parsers/parserContent_netskope-activity.md)<br> ↳ [s-netskope-activity](Parsers/parserContent_s-netskope-activity.md)<br><br> security-alert<br> ↳ [cef-netskope-alert](Parsers/parserContent_cef-netskope-alert.md)<br> ↳ [cef-netskope-alert-anomaly](Parsers/parserContent_cef-netskope-alert-anomaly.md)<br> ↳ [cef-netskope-alert-malsite](Parsers/parserContent_cef-netskope-alert-malsite.md)<br> ↳ [netskope-alert](Parsers/parserContent_netskope-alert.md)<br> ↳ [cef-netskope-alert-policy](Parsers/parserContent_cef-netskope-alert-policy.md)<br> ↳ [cef-netskope-alert-1](Parsers/parserContent_cef-netskope-alert-1.md)<br> ↳ [cef-netskope-alert-2](Parsers/parserContent_cef-netskope-alert-2.md)<br><br> web-activity-allowed<br> ↳ [cef-netskope-web-activity](Parsers/parserContent_cef-netskope-web-activity.md)<br> | T1048 - Exfiltration Over Alternative Protocol<br>T1066 - T1066<br>T1071 - Application Layer Protocol<br>T1078 - Valid Accounts<br>T1083 - File and Directory Discovery<br>T1086 - T1086<br>T1133 - External Remote Services<br>  | [<ul><li>70 Rules</li></ul><ul><li>40 Models</li></ul>](Rules_Models/r_m_netskope_netskope_active_platform_Compromised_Credentials.md) |
|       [Data Exfiltration](../../../UseCases/uc_data_exfiltration.md)       |  app-activity<br> ↳ [netskope-activity](Parsers/parserContent_netskope-activity.md)<br> ↳ [s-netskope-activity](Parsers/parserContent_s-netskope-activity.md)<br><br> app-login<br> ↳ [netskope-login](Parsers/parserContent_netskope-login.md)<br> ↳ [s-netskope-login](Parsers/parserContent_s-netskope-login.md)<br><br> dlp-alert<br> ↳ [cef-netskope-dlp-alert](Parsers/parserContent_cef-netskope-dlp-alert.md)<br> ↳ [cef-netskope-dlp-alert-1](Parsers/parserContent_cef-netskope-dlp-alert-1.md)<br> ↳ [netscope-dlp-alert-activity](Parsers/parserContent_netscope-dlp-alert-activity.md)<br> ↳ [netskope-dlp-alert](Parsers/parserContent_netskope-dlp-alert.md)<br><br> dlp-email-alert-out<br> ↳ [cef-netskope-dlp-email-alert-1](Parsers/parserContent_cef-netskope-dlp-email-alert-1.md)<br><br> file-delete<br> ↳ [netskope-activity](Parsers/parserContent_netskope-activity.md)<br> ↳ [s-netskope-activity](Parsers/parserContent_s-netskope-activity.md)<br><br> file-download<br> ↳ [netskope-activity](Parsers/parserContent_netskope-activity.md)<br> ↳ [s-netskope-activity](Parsers/parserContent_s-netskope-activity.md)<br><br> file-permission-change<br> ↳ [netskope-activity](Parsers/parserContent_netskope-activity.md)<br> ↳ [s-netskope-activity](Parsers/parserContent_s-netskope-activity.md)<br><br> file-read<br> ↳ [netskope-activity](Parsers/parserContent_netskope-activity.md)<br> ↳ [s-netskope-activity](Parsers/parserContent_s-netskope-activity.md)<br><br> file-upload<br> ↳ [netskope-activity](Parsers/parserContent_netskope-activity.md)<br> ↳ [s-netskope-activity](Parsers/parserContent_s-netskope-activity.md)<br><br> file-write<br> ↳ [netskope-activity](Parsers/parserContent_netskope-activity.md)<br> ↳ [s-netskope-activity](Parsers/parserContent_s-netskope-activity.md)<br><br> security-alert<br> ↳ [cef-netskope-alert](Parsers/parserContent_cef-netskope-alert.md)<br> ↳ [cef-netskope-alert-anomaly](Parsers/parserContent_cef-netskope-alert-anomaly.md)<br> ↳ [cef-netskope-alert-malsite](Parsers/parserContent_cef-netskope-alert-malsite.md)<br> ↳ [netskope-alert](Parsers/parserContent_netskope-alert.md)<br> ↳ [cef-netskope-alert-policy](Parsers/parserContent_cef-netskope-alert-policy.md)<br> ↳ [cef-netskope-alert-1](Parsers/parserContent_cef-netskope-alert-1.md)<br> ↳ [cef-netskope-alert-2](Parsers/parserContent_cef-netskope-alert-2.md)<br><br> web-activity-allowed<br> ↳ [cef-netskope-web-activity](Parsers/parserContent_cef-netskope-web-activity.md)<br> | T1041 - Exfiltration Over C2 Channel<br>T1048 - Exfiltration Over Alternative Protocol<br>T1083 - File and Directory Discovery<br>T1102 - Web Service<br>T1204 - User Execution<br>T1213 - Data from Information Repositories<br> | [<ul><li>54 Rules</li></ul><ul><li>27 Models</li></ul>](Rules_Models/r_m_netskope_netskope_active_platform_Data_Exfiltration.md)       |
|         [Data Extraction](../../../UseCases/uc_data_extraction.md)         |  app-activity<br> ↳ [netskope-activity](Parsers/parserContent_netskope-activity.md)<br> ↳ [s-netskope-activity](Parsers/parserContent_s-netskope-activity.md)<br><br> app-login<br> ↳ [netskope-login](Parsers/parserContent_netskope-login.md)<br> ↳ [s-netskope-login](Parsers/parserContent_s-netskope-login.md)<br><br> dlp-alert<br> ↳ [cef-netskope-dlp-alert](Parsers/parserContent_cef-netskope-dlp-alert.md)<br> ↳ [cef-netskope-dlp-alert-1](Parsers/parserContent_cef-netskope-dlp-alert-1.md)<br> ↳ [netscope-dlp-alert-activity](Parsers/parserContent_netscope-dlp-alert-activity.md)<br> ↳ [netskope-dlp-alert](Parsers/parserContent_netskope-dlp-alert.md)<br><br> dlp-email-alert-out<br> ↳ [cef-netskope-dlp-email-alert-1](Parsers/parserContent_cef-netskope-dlp-email-alert-1.md)<br><br> file-delete<br> ↳ [netskope-activity](Parsers/parserContent_netskope-activity.md)<br> ↳ [s-netskope-activity](Parsers/parserContent_s-netskope-activity.md)<br><br> file-download<br> ↳ [netskope-activity](Parsers/parserContent_netskope-activity.md)<br> ↳ [s-netskope-activity](Parsers/parserContent_s-netskope-activity.md)<br><br> file-permission-change<br> ↳ [netskope-activity](Parsers/parserContent_netskope-activity.md)<br> ↳ [s-netskope-activity](Parsers/parserContent_s-netskope-activity.md)<br><br> file-read<br> ↳ [netskope-activity](Parsers/parserContent_netskope-activity.md)<br> ↳ [s-netskope-activity](Parsers/parserContent_s-netskope-activity.md)<br><br> file-upload<br> ↳ [netskope-activity](Parsers/parserContent_netskope-activity.md)<br> ↳ [s-netskope-activity](Parsers/parserContent_s-netskope-activity.md)<br><br> file-write<br> ↳ [netskope-activity](Parsers/parserContent_netskope-activity.md)<br> ↳ [s-netskope-activity](Parsers/parserContent_s-netskope-activity.md)<br><br> security-alert<br> ↳ [cef-netskope-alert](Parsers/parserContent_cef-netskope-alert.md)<br> ↳ [cef-netskope-alert-anomaly](Parsers/parserContent_cef-netskope-alert-anomaly.md)<br> ↳ [cef-netskope-alert-malsite](Parsers/parserContent_cef-netskope-alert-malsite.md)<br> ↳ [netskope-alert](Parsers/parserContent_netskope-alert.md)<br> ↳ [cef-netskope-alert-policy](Parsers/parserContent_cef-netskope-alert-policy.md)<br> ↳ [cef-netskope-alert-1](Parsers/parserContent_cef-netskope-alert-1.md)<br> ↳ [cef-netskope-alert-2](Parsers/parserContent_cef-netskope-alert-2.md)<br><br> web-activity-allowed<br> ↳ [cef-netskope-web-activity](Parsers/parserContent_cef-netskope-web-activity.md)<br> | T1083 - File and Directory Discovery<br>                                                                                                                                                                                          | [<ul><li>1 Rules</li></ul><ul><li>1 Models</li></ul>](Rules_Models/r_m_netskope_netskope_active_platform_Data_Extraction.md)           |
|          [Internal Fraud](../../../UseCases/uc_internal_fraud.md)          |  app-activity<br> ↳ [netskope-activity](Parsers/parserContent_netskope-activity.md)<br> ↳ [s-netskope-activity](Parsers/parserContent_s-netskope-activity.md)<br><br> app-login<br> ↳ [netskope-login](Parsers/parserContent_netskope-login.md)<br> ↳ [s-netskope-login](Parsers/parserContent_s-netskope-login.md)<br><br> dlp-alert<br> ↳ [cef-netskope-dlp-alert](Parsers/parserContent_cef-netskope-dlp-alert.md)<br> ↳ [cef-netskope-dlp-alert-1](Parsers/parserContent_cef-netskope-dlp-alert-1.md)<br> ↳ [netscope-dlp-alert-activity](Parsers/parserContent_netscope-dlp-alert-activity.md)<br> ↳ [netskope-dlp-alert](Parsers/parserContent_netskope-dlp-alert.md)<br><br> dlp-email-alert-out<br> ↳ [cef-netskope-dlp-email-alert-1](Parsers/parserContent_cef-netskope-dlp-email-alert-1.md)<br><br> file-delete<br> ↳ [netskope-activity](Parsers/parserContent_netskope-activity.md)<br> ↳ [s-netskope-activity](Parsers/parserContent_s-netskope-activity.md)<br><br> file-download<br> ↳ [netskope-activity](Parsers/parserContent_netskope-activity.md)<br> ↳ [s-netskope-activity](Parsers/parserContent_s-netskope-activity.md)<br><br> file-permission-change<br> ↳ [netskope-activity](Parsers/parserContent_netskope-activity.md)<br> ↳ [s-netskope-activity](Parsers/parserContent_s-netskope-activity.md)<br><br> file-read<br> ↳ [netskope-activity](Parsers/parserContent_netskope-activity.md)<br> ↳ [s-netskope-activity](Parsers/parserContent_s-netskope-activity.md)<br><br> file-upload<br> ↳ [netskope-activity](Parsers/parserContent_netskope-activity.md)<br> ↳ [s-netskope-activity](Parsers/parserContent_s-netskope-activity.md)<br><br> file-write<br> ↳ [netskope-activity](Parsers/parserContent_netskope-activity.md)<br> ↳ [s-netskope-activity](Parsers/parserContent_s-netskope-activity.md)<br><br> security-alert<br> ↳ [cef-netskope-alert](Parsers/parserContent_cef-netskope-alert.md)<br> ↳ [cef-netskope-alert-anomaly](Parsers/parserContent_cef-netskope-alert-anomaly.md)<br> ↳ [cef-netskope-alert-malsite](Parsers/parserContent_cef-netskope-alert-malsite.md)<br> ↳ [netskope-alert](Parsers/parserContent_netskope-alert.md)<br> ↳ [cef-netskope-alert-policy](Parsers/parserContent_cef-netskope-alert-policy.md)<br> ↳ [cef-netskope-alert-1](Parsers/parserContent_cef-netskope-alert-1.md)<br> ↳ [cef-netskope-alert-2](Parsers/parserContent_cef-netskope-alert-2.md)<br><br> web-activity-allowed<br> ↳ [cef-netskope-web-activity](Parsers/parserContent_cef-netskope-web-activity.md)<br> | T1071 - Application Layer Protocol<br>T1078 - Valid Accounts<br>                                                                                                                                                                  | [<ul><li>16 Rules</li></ul><ul><li>11 Models</li></ul>](Rules_Models/r_m_netskope_netskope_active_platform_Internal_Fraud.md)          |
|        [Lateral Movement](../../../UseCases/uc_lateral_movement.md)        |  app-activity<br> ↳ [netskope-activity](Parsers/parserContent_netskope-activity.md)<br> ↳ [s-netskope-activity](Parsers/parserContent_s-netskope-activity.md)<br><br> app-login<br> ↳ [netskope-login](Parsers/parserContent_netskope-login.md)<br> ↳ [s-netskope-login](Parsers/parserContent_s-netskope-login.md)<br><br> dlp-alert<br> ↳ [cef-netskope-dlp-alert](Parsers/parserContent_cef-netskope-dlp-alert.md)<br> ↳ [cef-netskope-dlp-alert-1](Parsers/parserContent_cef-netskope-dlp-alert-1.md)<br> ↳ [netscope-dlp-alert-activity](Parsers/parserContent_netscope-dlp-alert-activity.md)<br> ↳ [netskope-dlp-alert](Parsers/parserContent_netskope-dlp-alert.md)<br><br> dlp-email-alert-out<br> ↳ [cef-netskope-dlp-email-alert-1](Parsers/parserContent_cef-netskope-dlp-email-alert-1.md)<br><br> file-delete<br> ↳ [netskope-activity](Parsers/parserContent_netskope-activity.md)<br> ↳ [s-netskope-activity](Parsers/parserContent_s-netskope-activity.md)<br><br> file-download<br> ↳ [netskope-activity](Parsers/parserContent_netskope-activity.md)<br> ↳ [s-netskope-activity](Parsers/parserContent_s-netskope-activity.md)<br><br> file-permission-change<br> ↳ [netskope-activity](Parsers/parserContent_netskope-activity.md)<br> ↳ [s-netskope-activity](Parsers/parserContent_s-netskope-activity.md)<br><br> file-read<br> ↳ [netskope-activity](Parsers/parserContent_netskope-activity.md)<br> ↳ [s-netskope-activity](Parsers/parserContent_s-netskope-activity.md)<br><br> file-upload<br> ↳ [netskope-activity](Parsers/parserContent_netskope-activity.md)<br> ↳ [s-netskope-activity](Parsers/parserContent_s-netskope-activity.md)<br><br> file-write<br> ↳ [netskope-activity](Parsers/parserContent_netskope-activity.md)<br> ↳ [s-netskope-activity](Parsers/parserContent_s-netskope-activity.md)<br><br> security-alert<br> ↳ [cef-netskope-alert](Parsers/parserContent_cef-netskope-alert.md)<br> ↳ [cef-netskope-alert-anomaly](Parsers/parserContent_cef-netskope-alert-anomaly.md)<br> ↳ [cef-netskope-alert-malsite](Parsers/parserContent_cef-netskope-alert-malsite.md)<br> ↳ [netskope-alert](Parsers/parserContent_netskope-alert.md)<br> ↳ [cef-netskope-alert-policy](Parsers/parserContent_cef-netskope-alert-policy.md)<br> ↳ [cef-netskope-alert-1](Parsers/parserContent_cef-netskope-alert-1.md)<br> ↳ [cef-netskope-alert-2](Parsers/parserContent_cef-netskope-alert-2.md)<br><br> web-activity-allowed<br> ↳ [cef-netskope-web-activity](Parsers/parserContent_cef-netskope-web-activity.md)<br> | T1071 - Application Layer Protocol<br>T1078 - Valid Accounts<br>T1133 - External Remote Services<br>                                                                                                                              | [<ul><li>10 Rules</li></ul><ul><li>8 Models</li></ul>](Rules_Models/r_m_netskope_netskope_active_platform_Lateral_Movement.md)         |
|       [Malware Detection](../../../UseCases/uc_malware_detection.md)       |  app-activity<br> ↳ [netskope-activity](Parsers/parserContent_netskope-activity.md)<br> ↳ [s-netskope-activity](Parsers/parserContent_s-netskope-activity.md)<br><br> app-login<br> ↳ [netskope-login](Parsers/parserContent_netskope-login.md)<br> ↳ [s-netskope-login](Parsers/parserContent_s-netskope-login.md)<br><br> dlp-alert<br> ↳ [cef-netskope-dlp-alert](Parsers/parserContent_cef-netskope-dlp-alert.md)<br> ↳ [cef-netskope-dlp-alert-1](Parsers/parserContent_cef-netskope-dlp-alert-1.md)<br> ↳ [netscope-dlp-alert-activity](Parsers/parserContent_netscope-dlp-alert-activity.md)<br> ↳ [netskope-dlp-alert](Parsers/parserContent_netskope-dlp-alert.md)<br><br> dlp-email-alert-out<br> ↳ [cef-netskope-dlp-email-alert-1](Parsers/parserContent_cef-netskope-dlp-email-alert-1.md)<br><br> file-delete<br> ↳ [netskope-activity](Parsers/parserContent_netskope-activity.md)<br> ↳ [s-netskope-activity](Parsers/parserContent_s-netskope-activity.md)<br><br> file-download<br> ↳ [netskope-activity](Parsers/parserContent_netskope-activity.md)<br> ↳ [s-netskope-activity](Parsers/parserContent_s-netskope-activity.md)<br><br> file-permission-change<br> ↳ [netskope-activity](Parsers/parserContent_netskope-activity.md)<br> ↳ [s-netskope-activity](Parsers/parserContent_s-netskope-activity.md)<br><br> file-read<br> ↳ [netskope-activity](Parsers/parserContent_netskope-activity.md)<br> ↳ [s-netskope-activity](Parsers/parserContent_s-netskope-activity.md)<br><br> file-upload<br> ↳ [netskope-activity](Parsers/parserContent_netskope-activity.md)<br> ↳ [s-netskope-activity](Parsers/parserContent_s-netskope-activity.md)<br><br> file-write<br> ↳ [netskope-activity](Parsers/parserContent_netskope-activity.md)<br> ↳ [s-netskope-activity](Parsers/parserContent_s-netskope-activity.md)<br><br> security-alert<br> ↳ [cef-netskope-alert](Parsers/parserContent_cef-netskope-alert.md)<br> ↳ [cef-netskope-alert-anomaly](Parsers/parserContent_cef-netskope-alert-anomaly.md)<br> ↳ [cef-netskope-alert-malsite](Parsers/parserContent_cef-netskope-alert-malsite.md)<br> ↳ [netskope-alert](Parsers/parserContent_netskope-alert.md)<br> ↳ [cef-netskope-alert-policy](Parsers/parserContent_cef-netskope-alert-policy.md)<br> ↳ [cef-netskope-alert-1](Parsers/parserContent_cef-netskope-alert-1.md)<br> ↳ [cef-netskope-alert-2](Parsers/parserContent_cef-netskope-alert-2.md)<br><br> web-activity-allowed<br> ↳ [cef-netskope-web-activity](Parsers/parserContent_cef-netskope-web-activity.md)<br> | T1066 - T1066<br>T1071 - Application Layer Protocol<br>T1075 - T1075<br>T1078 - Valid Accounts<br>T1086 - T1086<br>T1102 - Web Service<br>T1188 - T1188<br>T1189 - Drive-by Compromise<br>T1204 - User Execution<br>              | [<ul><li>46 Rules</li></ul><ul><li>14 Models</li></ul>](Rules_Models/r_m_netskope_netskope_active_platform_Malware_Detection.md)       |
|                   [Other](../../../UseCases/uc_other.md)                   |  app-activity<br> ↳ [netskope-activity](Parsers/parserContent_netskope-activity.md)<br> ↳ [s-netskope-activity](Parsers/parserContent_s-netskope-activity.md)<br><br> app-login<br> ↳ [netskope-login](Parsers/parserContent_netskope-login.md)<br> ↳ [s-netskope-login](Parsers/parserContent_s-netskope-login.md)<br><br> dlp-alert<br> ↳ [cef-netskope-dlp-alert](Parsers/parserContent_cef-netskope-dlp-alert.md)<br> ↳ [cef-netskope-dlp-alert-1](Parsers/parserContent_cef-netskope-dlp-alert-1.md)<br> ↳ [netscope-dlp-alert-activity](Parsers/parserContent_netscope-dlp-alert-activity.md)<br> ↳ [netskope-dlp-alert](Parsers/parserContent_netskope-dlp-alert.md)<br><br> dlp-email-alert-out<br> ↳ [cef-netskope-dlp-email-alert-1](Parsers/parserContent_cef-netskope-dlp-email-alert-1.md)<br><br> file-delete<br> ↳ [netskope-activity](Parsers/parserContent_netskope-activity.md)<br> ↳ [s-netskope-activity](Parsers/parserContent_s-netskope-activity.md)<br><br> file-download<br> ↳ [netskope-activity](Parsers/parserContent_netskope-activity.md)<br> ↳ [s-netskope-activity](Parsers/parserContent_s-netskope-activity.md)<br><br> file-permission-change<br> ↳ [netskope-activity](Parsers/parserContent_netskope-activity.md)<br> ↳ [s-netskope-activity](Parsers/parserContent_s-netskope-activity.md)<br><br> file-read<br> ↳ [netskope-activity](Parsers/parserContent_netskope-activity.md)<br> ↳ [s-netskope-activity](Parsers/parserContent_s-netskope-activity.md)<br><br> file-upload<br> ↳ [netskope-activity](Parsers/parserContent_netskope-activity.md)<br> ↳ [s-netskope-activity](Parsers/parserContent_s-netskope-activity.md)<br><br> file-write<br> ↳ [netskope-activity](Parsers/parserContent_netskope-activity.md)<br> ↳ [s-netskope-activity](Parsers/parserContent_s-netskope-activity.md)<br><br> security-alert<br> ↳ [cef-netskope-alert](Parsers/parserContent_cef-netskope-alert.md)<br> ↳ [cef-netskope-alert-anomaly](Parsers/parserContent_cef-netskope-alert-anomaly.md)<br> ↳ [cef-netskope-alert-malsite](Parsers/parserContent_cef-netskope-alert-malsite.md)<br> ↳ [netskope-alert](Parsers/parserContent_netskope-alert.md)<br> ↳ [cef-netskope-alert-policy](Parsers/parserContent_cef-netskope-alert-policy.md)<br> ↳ [cef-netskope-alert-1](Parsers/parserContent_cef-netskope-alert-1.md)<br> ↳ [cef-netskope-alert-2](Parsers/parserContent_cef-netskope-alert-2.md)<br><br> web-activity-allowed<br> ↳ [cef-netskope-web-activity](Parsers/parserContent_cef-netskope-web-activity.md)<br> | T1071 - Application Layer Protocol<br>T1496 - Resource Hijacking<br>                                                                                                                                                              | [<ul><li>3 Rules</li></ul>](Rules_Models/r_m_netskope_netskope_active_platform_Other.md)                                               |
|                [Phishing](../../../UseCases/uc_phishing.md)                |  app-activity<br> ↳ [netskope-activity](Parsers/parserContent_netskope-activity.md)<br> ↳ [s-netskope-activity](Parsers/parserContent_s-netskope-activity.md)<br><br> app-login<br> ↳ [netskope-login](Parsers/parserContent_netskope-login.md)<br> ↳ [s-netskope-login](Parsers/parserContent_s-netskope-login.md)<br><br> dlp-alert<br> ↳ [cef-netskope-dlp-alert](Parsers/parserContent_cef-netskope-dlp-alert.md)<br> ↳ [cef-netskope-dlp-alert-1](Parsers/parserContent_cef-netskope-dlp-alert-1.md)<br> ↳ [netscope-dlp-alert-activity](Parsers/parserContent_netscope-dlp-alert-activity.md)<br> ↳ [netskope-dlp-alert](Parsers/parserContent_netskope-dlp-alert.md)<br><br> dlp-email-alert-out<br> ↳ [cef-netskope-dlp-email-alert-1](Parsers/parserContent_cef-netskope-dlp-email-alert-1.md)<br><br> file-delete<br> ↳ [netskope-activity](Parsers/parserContent_netskope-activity.md)<br> ↳ [s-netskope-activity](Parsers/parserContent_s-netskope-activity.md)<br><br> file-download<br> ↳ [netskope-activity](Parsers/parserContent_netskope-activity.md)<br> ↳ [s-netskope-activity](Parsers/parserContent_s-netskope-activity.md)<br><br> file-permission-change<br> ↳ [netskope-activity](Parsers/parserContent_netskope-activity.md)<br> ↳ [s-netskope-activity](Parsers/parserContent_s-netskope-activity.md)<br><br> file-read<br> ↳ [netskope-activity](Parsers/parserContent_netskope-activity.md)<br> ↳ [s-netskope-activity](Parsers/parserContent_s-netskope-activity.md)<br><br> file-upload<br> ↳ [netskope-activity](Parsers/parserContent_netskope-activity.md)<br> ↳ [s-netskope-activity](Parsers/parserContent_s-netskope-activity.md)<br><br> file-write<br> ↳ [netskope-activity](Parsers/parserContent_netskope-activity.md)<br> ↳ [s-netskope-activity](Parsers/parserContent_s-netskope-activity.md)<br><br> security-alert<br> ↳ [cef-netskope-alert](Parsers/parserContent_cef-netskope-alert.md)<br> ↳ [cef-netskope-alert-anomaly](Parsers/parserContent_cef-netskope-alert-anomaly.md)<br> ↳ [cef-netskope-alert-malsite](Parsers/parserContent_cef-netskope-alert-malsite.md)<br> ↳ [netskope-alert](Parsers/parserContent_netskope-alert.md)<br> ↳ [cef-netskope-alert-policy](Parsers/parserContent_cef-netskope-alert-policy.md)<br> ↳ [cef-netskope-alert-1](Parsers/parserContent_cef-netskope-alert-1.md)<br> ↳ [cef-netskope-alert-2](Parsers/parserContent_cef-netskope-alert-2.md)<br><br> web-activity-allowed<br> ↳ [cef-netskope-web-activity](Parsers/parserContent_cef-netskope-web-activity.md)<br> | T1048 - Exfiltration Over Alternative Protocol<br>T1071 - Application Layer Protocol<br>                                                                                                                                          | [<ul><li>14 Rules</li></ul><ul><li>4 Models</li></ul>](Rules_Models/r_m_netskope_netskope_active_platform_Phishing.md)                 |
|     [Privileged Activity](../../../UseCases/uc_privileged_activity.md)     |  app-activity<br> ↳ [netskope-activity](Parsers/parserContent_netskope-activity.md)<br> ↳ [s-netskope-activity](Parsers/parserContent_s-netskope-activity.md)<br><br> app-login<br> ↳ [netskope-login](Parsers/parserContent_netskope-login.md)<br> ↳ [s-netskope-login](Parsers/parserContent_s-netskope-login.md)<br><br> dlp-alert<br> ↳ [cef-netskope-dlp-alert](Parsers/parserContent_cef-netskope-dlp-alert.md)<br> ↳ [cef-netskope-dlp-alert-1](Parsers/parserContent_cef-netskope-dlp-alert-1.md)<br> ↳ [netscope-dlp-alert-activity](Parsers/parserContent_netscope-dlp-alert-activity.md)<br> ↳ [netskope-dlp-alert](Parsers/parserContent_netskope-dlp-alert.md)<br><br> dlp-email-alert-out<br> ↳ [cef-netskope-dlp-email-alert-1](Parsers/parserContent_cef-netskope-dlp-email-alert-1.md)<br><br> file-delete<br> ↳ [netskope-activity](Parsers/parserContent_netskope-activity.md)<br> ↳ [s-netskope-activity](Parsers/parserContent_s-netskope-activity.md)<br><br> file-download<br> ↳ [netskope-activity](Parsers/parserContent_netskope-activity.md)<br> ↳ [s-netskope-activity](Parsers/parserContent_s-netskope-activity.md)<br><br> file-permission-change<br> ↳ [netskope-activity](Parsers/parserContent_netskope-activity.md)<br> ↳ [s-netskope-activity](Parsers/parserContent_s-netskope-activity.md)<br><br> file-read<br> ↳ [netskope-activity](Parsers/parserContent_netskope-activity.md)<br> ↳ [s-netskope-activity](Parsers/parserContent_s-netskope-activity.md)<br><br> file-upload<br> ↳ [netskope-activity](Parsers/parserContent_netskope-activity.md)<br> ↳ [s-netskope-activity](Parsers/parserContent_s-netskope-activity.md)<br><br> file-write<br> ↳ [netskope-activity](Parsers/parserContent_netskope-activity.md)<br> ↳ [s-netskope-activity](Parsers/parserContent_s-netskope-activity.md)<br><br> security-alert<br> ↳ [cef-netskope-alert](Parsers/parserContent_cef-netskope-alert.md)<br> ↳ [cef-netskope-alert-anomaly](Parsers/parserContent_cef-netskope-alert-anomaly.md)<br> ↳ [cef-netskope-alert-malsite](Parsers/parserContent_cef-netskope-alert-malsite.md)<br> ↳ [netskope-alert](Parsers/parserContent_netskope-alert.md)<br> ↳ [cef-netskope-alert-policy](Parsers/parserContent_cef-netskope-alert-policy.md)<br> ↳ [cef-netskope-alert-1](Parsers/parserContent_cef-netskope-alert-1.md)<br> ↳ [cef-netskope-alert-2](Parsers/parserContent_cef-netskope-alert-2.md)<br><br> web-activity-allowed<br> ↳ [cef-netskope-web-activity](Parsers/parserContent_cef-netskope-web-activity.md)<br> | T1048 - Exfiltration Over Alternative Protocol<br>T1068 - Exploitation for Privilege Escalation<br>T1078 - Valid Accounts<br>                                                                                                     | [<ul><li>6 Rules</li></ul><ul><li>3 Models</li></ul>](Rules_Models/r_m_netskope_netskope_active_platform_Privileged_Activity.md)       |
|    [Ransomware Detection](../../../UseCases/uc_ransomware_detection.md)    |  app-activity<br> ↳ [netskope-activity](Parsers/parserContent_netskope-activity.md)<br> ↳ [s-netskope-activity](Parsers/parserContent_s-netskope-activity.md)<br><br> app-login<br> ↳ [netskope-login](Parsers/parserContent_netskope-login.md)<br> ↳ [s-netskope-login](Parsers/parserContent_s-netskope-login.md)<br><br> dlp-alert<br> ↳ [cef-netskope-dlp-alert](Parsers/parserContent_cef-netskope-dlp-alert.md)<br> ↳ [cef-netskope-dlp-alert-1](Parsers/parserContent_cef-netskope-dlp-alert-1.md)<br> ↳ [netscope-dlp-alert-activity](Parsers/parserContent_netscope-dlp-alert-activity.md)<br> ↳ [netskope-dlp-alert](Parsers/parserContent_netskope-dlp-alert.md)<br><br> dlp-email-alert-out<br> ↳ [cef-netskope-dlp-email-alert-1](Parsers/parserContent_cef-netskope-dlp-email-alert-1.md)<br><br> file-delete<br> ↳ [netskope-activity](Parsers/parserContent_netskope-activity.md)<br> ↳ [s-netskope-activity](Parsers/parserContent_s-netskope-activity.md)<br><br> file-download<br> ↳ [netskope-activity](Parsers/parserContent_netskope-activity.md)<br> ↳ [s-netskope-activity](Parsers/parserContent_s-netskope-activity.md)<br><br> file-permission-change<br> ↳ [netskope-activity](Parsers/parserContent_netskope-activity.md)<br> ↳ [s-netskope-activity](Parsers/parserContent_s-netskope-activity.md)<br><br> file-read<br> ↳ [netskope-activity](Parsers/parserContent_netskope-activity.md)<br> ↳ [s-netskope-activity](Parsers/parserContent_s-netskope-activity.md)<br><br> file-upload<br> ↳ [netskope-activity](Parsers/parserContent_netskope-activity.md)<br> ↳ [s-netskope-activity](Parsers/parserContent_s-netskope-activity.md)<br><br> file-write<br> ↳ [netskope-activity](Parsers/parserContent_netskope-activity.md)<br> ↳ [s-netskope-activity](Parsers/parserContent_s-netskope-activity.md)<br><br> security-alert<br> ↳ [cef-netskope-alert](Parsers/parserContent_cef-netskope-alert.md)<br> ↳ [cef-netskope-alert-anomaly](Parsers/parserContent_cef-netskope-alert-anomaly.md)<br> ↳ [cef-netskope-alert-malsite](Parsers/parserContent_cef-netskope-alert-malsite.md)<br> ↳ [netskope-alert](Parsers/parserContent_netskope-alert.md)<br> ↳ [cef-netskope-alert-policy](Parsers/parserContent_cef-netskope-alert-policy.md)<br> ↳ [cef-netskope-alert-1](Parsers/parserContent_cef-netskope-alert-1.md)<br> ↳ [cef-netskope-alert-2](Parsers/parserContent_cef-netskope-alert-2.md)<br><br> web-activity-allowed<br> ↳ [cef-netskope-web-activity](Parsers/parserContent_cef-netskope-web-activity.md)<br> | T1066 - T1066<br>T1071 - Application Layer Protocol<br>T1075 - T1075<br>T1078 - Valid Accounts<br>T1086 - T1086<br>T1102 - Web Service<br>T1188 - T1188<br>T1189 - Drive-by Compromise<br>T1204 - User Execution<br>              | [<ul><li>45 Rules</li></ul><ul><li>13 Models</li></ul>](Rules_Models/r_m_netskope_netskope_active_platform_Ransomware_Detection.md)    |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                                                                                                                                                                           | Execution                                                           | Persistence                                                                                                                                      | Privilege Escalation                                                                                                                                          | Defense Evasion                                                     | Credential Access | Discovery                                                                         | Lateral Movement | Collection                                                                              | Command and Control                                                                                                                             | Exfiltration                                                                                                                                                                 | Impact                                                                  |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------------- | --------------------------------------------------------------------------------- | ---------------- | --------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------- |
| [External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Drive-by Compromise](https://attack.mitre.org/techniques/T1189)<br><br> | [User Execution](https://attack.mitre.org/techniques/T1204)<br><br> | [External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |                   | [File and Directory Discovery](https://attack.mitre.org/techniques/T1083)<br><br> |                  | [Data from Information Repositories](https://attack.mitre.org/techniques/T1213)<br><br> | [Web Service](https://attack.mitre.org/techniques/T1102)<br><br>[Application Layer Protocol](https://attack.mitre.org/techniques/T1071)<br><br> | [Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048)<br><br>[Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041)<br><br> | [Resource Hijacking](https://attack.mitre.org/techniques/T1496)<br><br> |