|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
|         [Cryptomining](../../../UseCases/uc_cryptomining.md)         |  failed-vpn-login<br> ↳[checkpoint-vpn-logout-1](Ps/pC_checkpointvpnlogout1.md)<br> ↳[checkpoint-vpn-logout-2](Ps/pC_checkpointvpnlogout2.md)<br><br> network-connection-failed<br> ↳[checkpoint-network-connection-5](Ps/pC_checkpointnetworkconnection5.md)<br><br> network-connection-successful<br> ↳[checkpoint-network-connection-5](Ps/pC_checkpointnetworkconnection5.md)<br><br> vpn-login<br> ↳[checkpoint-vpn-login-4](Ps/pC_checkpointvpnlogin4.md)<br><br> web-activity-allowed<br> ↳[checkpoint-vpn-login-4](Ps/pC_checkpointvpnlogin4.md)<br> ↳[checkpoint-vpn-login-5](Ps/pC_checkpointvpnlogin5.md)<br> | T1071.001 - Application Layer Protocol: Web Protocols<br>T1496 - Resource Hijacking<br>    | [<ul><li>3 Rules</li></ul>](RM/r_m_check_point_software_check_point_identity_awareness_Cryptomining.md)    |
|    [Data Exfiltration](../../../UseCases/uc_data_exfiltration.md)    |  failed-vpn-login<br> ↳[checkpoint-vpn-logout-1](Ps/pC_checkpointvpnlogout1.md)<br> ↳[checkpoint-vpn-logout-2](Ps/pC_checkpointvpnlogout2.md)<br><br> network-connection-failed<br> ↳[checkpoint-network-connection-5](Ps/pC_checkpointnetworkconnection5.md)<br><br> network-connection-successful<br> ↳[checkpoint-network-connection-5](Ps/pC_checkpointnetworkconnection5.md)<br><br> vpn-login<br> ↳[checkpoint-vpn-login-4](Ps/pC_checkpointvpnlogin4.md)<br><br> web-activity-allowed<br> ↳[checkpoint-vpn-login-4](Ps/pC_checkpointvpnlogin4.md)<br> ↳[checkpoint-vpn-login-5](Ps/pC_checkpointvpnlogin5.md)<br> | T1030 - Data Transfer Size Limits<br>T1071.001 - Application Layer Protocol: Web Protocols<br>T1567.002 - Exfiltration Over Web Service: Exfiltration to Cloud Storage<br>T1568 - Dynamic Resolution<br>    | [<ul><li>6 Rules</li></ul><ul><li>2 Models</li></ul>](RM/r_m_check_point_software_check_point_identity_awareness_Data_Exfiltration.md)    |
|    [Data Leak](../../../UseCases/uc_data_leak.md)    |  failed-vpn-login<br> ↳[checkpoint-vpn-logout-1](Ps/pC_checkpointvpnlogout1.md)<br> ↳[checkpoint-vpn-logout-2](Ps/pC_checkpointvpnlogout2.md)<br><br> network-connection-failed<br> ↳[checkpoint-network-connection-5](Ps/pC_checkpointnetworkconnection5.md)<br><br> network-connection-successful<br> ↳[checkpoint-network-connection-5](Ps/pC_checkpointnetworkconnection5.md)<br><br> vpn-login<br> ↳[checkpoint-vpn-login-4](Ps/pC_checkpointvpnlogin4.md)<br><br> web-activity-allowed<br> ↳[checkpoint-vpn-login-4](Ps/pC_checkpointvpnlogin4.md)<br> ↳[checkpoint-vpn-login-5](Ps/pC_checkpointvpnlogin5.md)<br> | T1030 - Data Transfer Size Limits<br>T1071.001 - Application Layer Protocol: Web Protocols<br>T1567.002 - Exfiltration Over Web Service: Exfiltration to Cloud Storage<br>    | [<ul><li>6 Rules</li></ul><ul><li>3 Models</li></ul>](RM/r_m_check_point_software_check_point_identity_awareness_Data_Leak.md)    |
|    [Evasion](../../../UseCases/uc_evasion.md)    |  failed-vpn-login<br> ↳[checkpoint-vpn-logout-1](Ps/pC_checkpointvpnlogout1.md)<br> ↳[checkpoint-vpn-logout-2](Ps/pC_checkpointvpnlogout2.md)<br><br> network-connection-failed<br> ↳[checkpoint-network-connection-5](Ps/pC_checkpointnetworkconnection5.md)<br><br> network-connection-successful<br> ↳[checkpoint-network-connection-5](Ps/pC_checkpointnetworkconnection5.md)<br><br> vpn-login<br> ↳[checkpoint-vpn-login-4](Ps/pC_checkpointvpnlogin4.md)<br><br> web-activity-allowed<br> ↳[checkpoint-vpn-login-4](Ps/pC_checkpointvpnlogin4.md)<br> ↳[checkpoint-vpn-login-5](Ps/pC_checkpointvpnlogin5.md)<br> | T1071.001 - Application Layer Protocol: Web Protocols<br>T1090.003 - Proxy: Multi-hop Proxy<br>T1090.004 - T1090.004<br>    | [<ul><li>9 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_check_point_software_check_point_identity_awareness_Evasion.md)    |
|     [Lateral Movement](../../../UseCases/uc_lateral_movement.md)     |  failed-vpn-login<br> ↳[checkpoint-vpn-logout-1](Ps/pC_checkpointvpnlogout1.md)<br> ↳[checkpoint-vpn-logout-2](Ps/pC_checkpointvpnlogout2.md)<br><br> network-connection-failed<br> ↳[checkpoint-network-connection-5](Ps/pC_checkpointnetworkconnection5.md)<br><br> network-connection-successful<br> ↳[checkpoint-network-connection-5](Ps/pC_checkpointnetworkconnection5.md)<br><br> vpn-login<br> ↳[checkpoint-vpn-login-4](Ps/pC_checkpointvpnlogin4.md)<br><br> web-activity-allowed<br> ↳[checkpoint-vpn-login-4](Ps/pC_checkpointvpnlogin4.md)<br> ↳[checkpoint-vpn-login-5](Ps/pC_checkpointvpnlogin5.md)<br> | T1071 - Application Layer Protocol<br>T1090.002 - Proxy: External Proxy<br>T1205.001 - T1205.001<br>T1571 - Non-Standard Port<br>    | [<ul><li>52 Rules</li></ul><ul><li>20 Models</li></ul>](RM/r_m_check_point_software_check_point_identity_awareness_Lateral_Movement.md)   |
|    [Malware](../../../UseCases/uc_malware.md)    |  failed-vpn-login<br> ↳[checkpoint-vpn-logout-1](Ps/pC_checkpointvpnlogout1.md)<br> ↳[checkpoint-vpn-logout-2](Ps/pC_checkpointvpnlogout2.md)<br><br> network-connection-failed<br> ↳[checkpoint-network-connection-5](Ps/pC_checkpointnetworkconnection5.md)<br><br> network-connection-successful<br> ↳[checkpoint-network-connection-5](Ps/pC_checkpointnetworkconnection5.md)<br><br> vpn-login<br> ↳[checkpoint-vpn-login-4](Ps/pC_checkpointvpnlogin4.md)<br><br> web-activity-allowed<br> ↳[checkpoint-vpn-login-4](Ps/pC_checkpointvpnlogin4.md)<br> ↳[checkpoint-vpn-login-5](Ps/pC_checkpointvpnlogin5.md)<br> | T1071 - Application Layer Protocol<br>T1071.001 - Application Layer Protocol: Web Protocols<br>T1078 - Valid Accounts<br>T1090.003 - Proxy: Multi-hop Proxy<br>T1189 - Drive-by Compromise<br>T1204.001 - T1204.001<br>T1566.002 - Phishing: Spearphishing Link<br>T1568.002 - Dynamic Resolution: Domain Generation Algorithms<br> | [<ul><li>31 Rules</li></ul><ul><li>8 Models</li></ul>](RM/r_m_check_point_software_check_point_identity_awareness_Malware.md)    |
|    [Phishing](../../../UseCases/uc_phishing.md)    |  failed-vpn-login<br> ↳[checkpoint-vpn-logout-1](Ps/pC_checkpointvpnlogout1.md)<br> ↳[checkpoint-vpn-logout-2](Ps/pC_checkpointvpnlogout2.md)<br><br> network-connection-failed<br> ↳[checkpoint-network-connection-5](Ps/pC_checkpointnetworkconnection5.md)<br><br> network-connection-successful<br> ↳[checkpoint-network-connection-5](Ps/pC_checkpointnetworkconnection5.md)<br><br> vpn-login<br> ↳[checkpoint-vpn-login-4](Ps/pC_checkpointvpnlogin4.md)<br><br> web-activity-allowed<br> ↳[checkpoint-vpn-login-4](Ps/pC_checkpointvpnlogin4.md)<br> ↳[checkpoint-vpn-login-5](Ps/pC_checkpointvpnlogin5.md)<br> | T1071.001 - Application Layer Protocol: Web Protocols<br>T1566.002 - Phishing: Spearphishing Link<br>    | [<ul><li>3 Rules</li></ul>](RM/r_m_check_point_software_check_point_identity_awareness_Phishing.md)    |
|      [Privilege Abuse](../../../UseCases/uc_privilege_abuse.md)      |  failed-vpn-login<br> ↳[checkpoint-vpn-logout-1](Ps/pC_checkpointvpnlogout1.md)<br> ↳[checkpoint-vpn-logout-2](Ps/pC_checkpointvpnlogout2.md)<br><br> network-connection-failed<br> ↳[checkpoint-network-connection-5](Ps/pC_checkpointnetworkconnection5.md)<br><br> network-connection-successful<br> ↳[checkpoint-network-connection-5](Ps/pC_checkpointnetworkconnection5.md)<br><br> vpn-login<br> ↳[checkpoint-vpn-login-4](Ps/pC_checkpointvpnlogin4.md)<br><br> web-activity-allowed<br> ↳[checkpoint-vpn-login-4](Ps/pC_checkpointvpnlogin4.md)<br> ↳[checkpoint-vpn-login-5](Ps/pC_checkpointvpnlogin5.md)<br> | T1133 - External Remote Services<br>    | [<ul><li>3 Rules</li></ul>](RM/r_m_check_point_software_check_point_identity_awareness_Privilege_Abuse.md)    |
|  [Privileged Activity](../../../UseCases/uc_privileged_activity.md)  |  failed-vpn-login<br> ↳[checkpoint-vpn-logout-1](Ps/pC_checkpointvpnlogout1.md)<br> ↳[checkpoint-vpn-logout-2](Ps/pC_checkpointvpnlogout2.md)<br><br> network-connection-failed<br> ↳[checkpoint-network-connection-5](Ps/pC_checkpointnetworkconnection5.md)<br><br> network-connection-successful<br> ↳[checkpoint-network-connection-5](Ps/pC_checkpointnetworkconnection5.md)<br><br> vpn-login<br> ↳[checkpoint-vpn-login-4](Ps/pC_checkpointvpnlogin4.md)<br><br> web-activity-allowed<br> ↳[checkpoint-vpn-login-4](Ps/pC_checkpointvpnlogin4.md)<br> ↳[checkpoint-vpn-login-5](Ps/pC_checkpointvpnlogin5.md)<br> | T1071.001 - Application Layer Protocol: Web Protocols<br>T1102 - Web Service<br>T1133 - External Remote Services<br>    | [<ul><li>4 Rules</li></ul>](RM/r_m_check_point_software_check_point_identity_awareness_Privileged_Activity.md)    |
|    [Ransomware](../../../UseCases/uc_ransomware.md)    |  failed-vpn-login<br> ↳[checkpoint-vpn-logout-1](Ps/pC_checkpointvpnlogout1.md)<br> ↳[checkpoint-vpn-logout-2](Ps/pC_checkpointvpnlogout2.md)<br><br> network-connection-failed<br> ↳[checkpoint-network-connection-5](Ps/pC_checkpointnetworkconnection5.md)<br><br> network-connection-successful<br> ↳[checkpoint-network-connection-5](Ps/pC_checkpointnetworkconnection5.md)<br><br> vpn-login<br> ↳[checkpoint-vpn-login-4](Ps/pC_checkpointvpnlogin4.md)<br><br> web-activity-allowed<br> ↳[checkpoint-vpn-login-4](Ps/pC_checkpointvpnlogin4.md)<br> ↳[checkpoint-vpn-login-5](Ps/pC_checkpointvpnlogin5.md)<br> | T1071 - Application Layer Protocol<br>T1071.001 - Application Layer Protocol: Web Protocols<br>T1078 - Valid Accounts<br>    | [<ul><li>3 Rules</li></ul>](RM/r_m_check_point_software_check_point_identity_awareness_Ransomware.md)    |
| [Workforce Protection](../../../UseCases/uc_workforce_protection.md) |  failed-vpn-login<br> ↳[checkpoint-vpn-logout-1](Ps/pC_checkpointvpnlogout1.md)<br> ↳[checkpoint-vpn-logout-2](Ps/pC_checkpointvpnlogout2.md)<br><br> network-connection-failed<br> ↳[checkpoint-network-connection-5](Ps/pC_checkpointnetworkconnection5.md)<br><br> network-connection-successful<br> ↳[checkpoint-network-connection-5](Ps/pC_checkpointnetworkconnection5.md)<br><br> vpn-login<br> ↳[checkpoint-vpn-login-4](Ps/pC_checkpointvpnlogin4.md)<br><br> web-activity-allowed<br> ↳[checkpoint-vpn-login-4](Ps/pC_checkpointvpnlogin4.md)<br> ↳[checkpoint-vpn-login-5](Ps/pC_checkpointvpnlogin5.md)<br> | T1071.001 - Application Layer Protocol: Web Protocols<br>    | [<ul><li>5 Rules</li></ul><ul><li>2 Models</li></ul>](RM/r_m_check_point_software_check_point_identity_awareness_Workforce_Protection.md) |