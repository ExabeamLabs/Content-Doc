|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
|        [Cryptomining](../../../UseCases/uc_cryptomining.md)        |  app-activity-failed<br> ↳[airlock-logout](Ps/pC_airlocklogout.md)<br> ↳[airlock-disconnect](Ps/pC_airlockdisconnect.md)<br><br> app-login<br> ↳[airlock-login-failed](Ps/pC_airlockloginfailed.md)<br><br> database-query<br> ↳[airlock-login-success](Ps/pC_airlockloginsuccess.md)<br><br> failed-app-login<br> ↳[airlock-file-upload](Ps/pC_airlockfileupload.md)<br><br> file-delete<br> ↳[airlock-network-connection](Ps/pC_airlocknetworkconnection.md)<br><br> file-download<br> ↳[airlock-create-folder](Ps/pC_airlockcreatefolder.md)<br> ↳[airlock-rename-folder](Ps/pC_airlockrenamefolder.md)<br><br> file-upload<br> ↳[airlock-file-download](Ps/pC_airlockfiledownload.md)<br><br> file-write<br> ↳[airlock-file-delete](Ps/pC_airlockfiledelete.md)<br><br> network-connection-successful<br> ↳[airlock-file-upload-failed](Ps/pC_airlockfileuploadfailed.md)<br> ↳[airlock-file-download-failed](Ps/pC_airlockfiledownloadfailed.md)<br> | T1496 - Resource Hijacking<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_airlock_airlock_Cryptomining.md)    |
|         [Data Access](../../../UseCases/uc_data_access.md)         |  app-activity-failed<br> ↳[airlock-logout](Ps/pC_airlocklogout.md)<br> ↳[airlock-disconnect](Ps/pC_airlockdisconnect.md)<br><br> app-login<br> ↳[airlock-login-failed](Ps/pC_airlockloginfailed.md)<br><br> database-query<br> ↳[airlock-login-success](Ps/pC_airlockloginsuccess.md)<br><br> failed-app-login<br> ↳[airlock-file-upload](Ps/pC_airlockfileupload.md)<br><br> file-delete<br> ↳[airlock-network-connection](Ps/pC_airlocknetworkconnection.md)<br><br> file-download<br> ↳[airlock-create-folder](Ps/pC_airlockcreatefolder.md)<br> ↳[airlock-rename-folder](Ps/pC_airlockrenamefolder.md)<br><br> file-upload<br> ↳[airlock-file-download](Ps/pC_airlockfiledownload.md)<br><br> file-write<br> ↳[airlock-file-delete](Ps/pC_airlockfiledelete.md)<br><br> network-connection-successful<br> ↳[airlock-file-upload-failed](Ps/pC_airlockfileuploadfailed.md)<br> ↳[airlock-file-download-failed](Ps/pC_airlockfiledownloadfailed.md)<br> | T1078 - Valid Accounts<br>T1083 - File and Directory Discovery<br>T1213 - Data from Information Repositories<br>    | [<ul><li>46 Rules</li></ul><ul><li>25 Models</li></ul>](RM/r_m_airlock_airlock_Data_Access.md)      |
|   [Data Exfiltration](../../../UseCases/uc_data_exfiltration.md)   |  app-activity-failed<br> ↳[airlock-logout](Ps/pC_airlocklogout.md)<br> ↳[airlock-disconnect](Ps/pC_airlockdisconnect.md)<br><br> app-login<br> ↳[airlock-login-failed](Ps/pC_airlockloginfailed.md)<br><br> database-query<br> ↳[airlock-login-success](Ps/pC_airlockloginsuccess.md)<br><br> failed-app-login<br> ↳[airlock-file-upload](Ps/pC_airlockfileupload.md)<br><br> file-delete<br> ↳[airlock-network-connection](Ps/pC_airlocknetworkconnection.md)<br><br> file-download<br> ↳[airlock-create-folder](Ps/pC_airlockcreatefolder.md)<br> ↳[airlock-rename-folder](Ps/pC_airlockrenamefolder.md)<br><br> file-upload<br> ↳[airlock-file-download](Ps/pC_airlockfiledownload.md)<br><br> file-write<br> ↳[airlock-file-delete](Ps/pC_airlockfiledelete.md)<br><br> network-connection-successful<br> ↳[airlock-file-upload-failed](Ps/pC_airlockfileuploadfailed.md)<br> ↳[airlock-file-download-failed](Ps/pC_airlockfiledownloadfailed.md)<br> | T1204 - User Execution<br>    | [<ul><li>2 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_airlock_airlock_Data_Exfiltration.md)  |
|    [Data Leak](../../../UseCases/uc_data_leak.md)    |  app-activity-failed<br> ↳[airlock-logout](Ps/pC_airlocklogout.md)<br> ↳[airlock-disconnect](Ps/pC_airlockdisconnect.md)<br><br> app-login<br> ↳[airlock-login-failed](Ps/pC_airlockloginfailed.md)<br><br> database-query<br> ↳[airlock-login-success](Ps/pC_airlockloginsuccess.md)<br><br> failed-app-login<br> ↳[airlock-file-upload](Ps/pC_airlockfileupload.md)<br><br> file-delete<br> ↳[airlock-network-connection](Ps/pC_airlocknetworkconnection.md)<br><br> file-download<br> ↳[airlock-create-folder](Ps/pC_airlockcreatefolder.md)<br> ↳[airlock-rename-folder](Ps/pC_airlockrenamefolder.md)<br><br> file-upload<br> ↳[airlock-file-download](Ps/pC_airlockfiledownload.md)<br><br> file-write<br> ↳[airlock-file-delete](Ps/pC_airlockfiledelete.md)<br><br> network-connection-successful<br> ↳[airlock-file-upload-failed](Ps/pC_airlockfileuploadfailed.md)<br> ↳[airlock-file-download-failed](Ps/pC_airlockfiledownloadfailed.md)<br> | T1114.001 - T1114.001<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_airlock_airlock_Data_Leak.md)    |
| [Destruction of Data](../../../UseCases/uc_destruction_of_data.md) |  app-activity-failed<br> ↳[airlock-logout](Ps/pC_airlocklogout.md)<br> ↳[airlock-disconnect](Ps/pC_airlockdisconnect.md)<br><br> app-login<br> ↳[airlock-login-failed](Ps/pC_airlockloginfailed.md)<br><br> database-query<br> ↳[airlock-login-success](Ps/pC_airlockloginsuccess.md)<br><br> failed-app-login<br> ↳[airlock-file-upload](Ps/pC_airlockfileupload.md)<br><br> file-delete<br> ↳[airlock-network-connection](Ps/pC_airlocknetworkconnection.md)<br><br> file-download<br> ↳[airlock-create-folder](Ps/pC_airlockcreatefolder.md)<br> ↳[airlock-rename-folder](Ps/pC_airlockrenamefolder.md)<br><br> file-upload<br> ↳[airlock-file-download](Ps/pC_airlockfiledownload.md)<br><br> file-write<br> ↳[airlock-file-delete](Ps/pC_airlockfiledelete.md)<br><br> network-connection-successful<br> ↳[airlock-file-upload-failed](Ps/pC_airlockfileuploadfailed.md)<br> ↳[airlock-file-download-failed](Ps/pC_airlockfiledownloadfailed.md)<br> | T1070.004 - Indicator Removal on Host: File Deletion<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_airlock_airlock_Destruction_of_Data.md)    |
|    [Evasion](../../../UseCases/uc_evasion.md)    |  app-activity-failed<br> ↳[airlock-logout](Ps/pC_airlocklogout.md)<br> ↳[airlock-disconnect](Ps/pC_airlockdisconnect.md)<br><br> app-login<br> ↳[airlock-login-failed](Ps/pC_airlockloginfailed.md)<br><br> database-query<br> ↳[airlock-login-success](Ps/pC_airlockloginsuccess.md)<br><br> failed-app-login<br> ↳[airlock-file-upload](Ps/pC_airlockfileupload.md)<br><br> file-delete<br> ↳[airlock-network-connection](Ps/pC_airlocknetworkconnection.md)<br><br> file-download<br> ↳[airlock-create-folder](Ps/pC_airlockcreatefolder.md)<br> ↳[airlock-rename-folder](Ps/pC_airlockrenamefolder.md)<br><br> file-upload<br> ↳[airlock-file-download](Ps/pC_airlockfiledownload.md)<br><br> file-write<br> ↳[airlock-file-delete](Ps/pC_airlockfiledelete.md)<br><br> network-connection-successful<br> ↳[airlock-file-upload-failed](Ps/pC_airlockfileuploadfailed.md)<br> ↳[airlock-file-download-failed](Ps/pC_airlockfiledownloadfailed.md)<br> | T1090.003 - Proxy: Multi-hop Proxy<br>    | [<ul><li>3 Rules</li></ul>](RM/r_m_airlock_airlock_Evasion.md)    |
|    [Lateral Movement](../../../UseCases/uc_lateral_movement.md)    |  app-activity-failed<br> ↳[airlock-logout](Ps/pC_airlocklogout.md)<br> ↳[airlock-disconnect](Ps/pC_airlockdisconnect.md)<br><br> app-login<br> ↳[airlock-login-failed](Ps/pC_airlockloginfailed.md)<br><br> database-query<br> ↳[airlock-login-success](Ps/pC_airlockloginsuccess.md)<br><br> failed-app-login<br> ↳[airlock-file-upload](Ps/pC_airlockfileupload.md)<br><br> file-delete<br> ↳[airlock-network-connection](Ps/pC_airlocknetworkconnection.md)<br><br> file-download<br> ↳[airlock-create-folder](Ps/pC_airlockcreatefolder.md)<br> ↳[airlock-rename-folder](Ps/pC_airlockrenamefolder.md)<br><br> file-upload<br> ↳[airlock-file-download](Ps/pC_airlockfiledownload.md)<br><br> file-write<br> ↳[airlock-file-delete](Ps/pC_airlockfiledelete.md)<br><br> network-connection-successful<br> ↳[airlock-file-upload-failed](Ps/pC_airlockfileuploadfailed.md)<br> ↳[airlock-file-download-failed](Ps/pC_airlockfiledownloadfailed.md)<br> | T1071 - Application Layer Protocol<br>T1090.002 - Proxy: External Proxy<br>T1205.001 - T1205.001<br>T1571 - Non-Standard Port<br>    | [<ul><li>37 Rules</li></ul><ul><li>17 Models</li></ul>](RM/r_m_airlock_airlock_Lateral_Movement.md) |
|    [Malware](../../../UseCases/uc_malware.md)    |  app-activity-failed<br> ↳[airlock-logout](Ps/pC_airlocklogout.md)<br> ↳[airlock-disconnect](Ps/pC_airlockdisconnect.md)<br><br> app-login<br> ↳[airlock-login-failed](Ps/pC_airlockloginfailed.md)<br><br> database-query<br> ↳[airlock-login-success](Ps/pC_airlockloginsuccess.md)<br><br> failed-app-login<br> ↳[airlock-file-upload](Ps/pC_airlockfileupload.md)<br><br> file-delete<br> ↳[airlock-network-connection](Ps/pC_airlocknetworkconnection.md)<br><br> file-download<br> ↳[airlock-create-folder](Ps/pC_airlockcreatefolder.md)<br> ↳[airlock-rename-folder](Ps/pC_airlockrenamefolder.md)<br><br> file-upload<br> ↳[airlock-file-download](Ps/pC_airlockfiledownload.md)<br><br> file-write<br> ↳[airlock-file-delete](Ps/pC_airlockfiledelete.md)<br><br> network-connection-successful<br> ↳[airlock-file-upload-failed](Ps/pC_airlockfileuploadfailed.md)<br> ↳[airlock-file-download-failed](Ps/pC_airlockfiledownloadfailed.md)<br> | T1003.002 - T1003.002<br>T1027 - Obfuscated Files or Information<br>T1055.012 - T1055.012<br>T1071 - Application Layer Protocol<br>T1078 - Valid Accounts<br>T1204 - User Execution<br>T1218.011 - Signed Binary Proxy Execution: Rundll32<br> | [<ul><li>8 Rules</li></ul><ul><li>3 Models</li></ul>](RM/r_m_airlock_airlock_Malware.md)    |
|     [Privilege Abuse](../../../UseCases/uc_privilege_abuse.md)     |  app-activity-failed<br> ↳[airlock-logout](Ps/pC_airlocklogout.md)<br> ↳[airlock-disconnect](Ps/pC_airlockdisconnect.md)<br><br> app-login<br> ↳[airlock-login-failed](Ps/pC_airlockloginfailed.md)<br><br> database-query<br> ↳[airlock-login-success](Ps/pC_airlockloginsuccess.md)<br><br> failed-app-login<br> ↳[airlock-file-upload](Ps/pC_airlockfileupload.md)<br><br> file-delete<br> ↳[airlock-network-connection](Ps/pC_airlocknetworkconnection.md)<br><br> file-download<br> ↳[airlock-create-folder](Ps/pC_airlockcreatefolder.md)<br> ↳[airlock-rename-folder](Ps/pC_airlockrenamefolder.md)<br><br> file-upload<br> ↳[airlock-file-download](Ps/pC_airlockfiledownload.md)<br><br> file-write<br> ↳[airlock-file-delete](Ps/pC_airlockfiledelete.md)<br><br> network-connection-successful<br> ↳[airlock-file-upload-failed](Ps/pC_airlockfileuploadfailed.md)<br> ↳[airlock-file-download-failed](Ps/pC_airlockfiledownloadfailed.md)<br> | T1078 - Valid Accounts<br>    | [<ul><li>3 Rules</li></ul>](RM/r_m_airlock_airlock_Privilege_Abuse.md)    |
| [Privileged Activity](../../../UseCases/uc_privileged_activity.md) |  app-activity-failed<br> ↳[airlock-logout](Ps/pC_airlocklogout.md)<br> ↳[airlock-disconnect](Ps/pC_airlockdisconnect.md)<br><br> app-login<br> ↳[airlock-login-failed](Ps/pC_airlockloginfailed.md)<br><br> database-query<br> ↳[airlock-login-success](Ps/pC_airlockloginsuccess.md)<br><br> failed-app-login<br> ↳[airlock-file-upload](Ps/pC_airlockfileupload.md)<br><br> file-delete<br> ↳[airlock-network-connection](Ps/pC_airlocknetworkconnection.md)<br><br> file-download<br> ↳[airlock-create-folder](Ps/pC_airlockcreatefolder.md)<br> ↳[airlock-rename-folder](Ps/pC_airlockrenamefolder.md)<br><br> file-upload<br> ↳[airlock-file-download](Ps/pC_airlockfiledownload.md)<br><br> file-write<br> ↳[airlock-file-delete](Ps/pC_airlockfiledelete.md)<br><br> network-connection-successful<br> ↳[airlock-file-upload-failed](Ps/pC_airlockfileuploadfailed.md)<br> ↳[airlock-file-download-failed](Ps/pC_airlockfiledownloadfailed.md)<br> | T1078 - Valid Accounts<br>    | [<ul><li>2 Rules</li></ul>](RM/r_m_airlock_airlock_Privileged_Activity.md)    |
|          [Ransomware](../../../UseCases/uc_ransomware.md)          |  app-activity-failed<br> ↳[airlock-logout](Ps/pC_airlocklogout.md)<br> ↳[airlock-disconnect](Ps/pC_airlockdisconnect.md)<br><br> app-login<br> ↳[airlock-login-failed](Ps/pC_airlockloginfailed.md)<br><br> database-query<br> ↳[airlock-login-success](Ps/pC_airlockloginsuccess.md)<br><br> failed-app-login<br> ↳[airlock-file-upload](Ps/pC_airlockfileupload.md)<br><br> file-delete<br> ↳[airlock-network-connection](Ps/pC_airlocknetworkconnection.md)<br><br> file-download<br> ↳[airlock-create-folder](Ps/pC_airlockcreatefolder.md)<br> ↳[airlock-rename-folder](Ps/pC_airlockrenamefolder.md)<br><br> file-upload<br> ↳[airlock-file-download](Ps/pC_airlockfiledownload.md)<br><br> file-write<br> ↳[airlock-file-delete](Ps/pC_airlockfiledelete.md)<br><br> network-connection-successful<br> ↳[airlock-file-upload-failed](Ps/pC_airlockfileuploadfailed.md)<br> ↳[airlock-file-download-failed](Ps/pC_airlockfiledownloadfailed.md)<br> | T1078 - Valid Accounts<br>T1486 - Data Encrypted for Impact<br>    | [<ul><li>2 Rules</li></ul>](RM/r_m_airlock_airlock_Ransomware.md)    |