Vendor: Oracle
==============
Product: Access Manager
-----------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  78   |   33   |     8      |      5      |    5    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Abnormal Authentication & Access](../../../UseCases/uc_abnormal_authentication_&_access.md) |  app-activity<br> ↳[q-oam-app-login](Ps/pC_qoamapplogin.md)<br> ↳[s-oam-app-login](Ps/pC_soamapplogin.md)<br><br> app-login<br> ↳[s-oam-app-login-1](Ps/pC_soamapplogin1.md)<br> ↳[s-oam-app-login](Ps/pC_soamapplogin.md)<br><br> authentication-successful<br> ↳[oracle-access-manager](Ps/pC_oracleaccessmanager.md)<br><br> failed-app-login<br> ↳[q-oam-auth-successful](Ps/pC_qoamauthsuccessful.md)<br><br> failed-physical-access<br> ↳[q-oam-app-activity-5](Ps/pC_qoamappactivity5.md)<br> ↳[q-oam-app-activity-4](Ps/pC_qoamappactivity4.md)<br> ↳[q-oam-app-activity-7](Ps/pC_qoamappactivity7.md)<br> ↳[q-oam-app-activity-6](Ps/pC_qoamappactivity6.md)<br> ↳[q-oam-app-activity-10](Ps/pC_qoamappactivity10.md)<br> ↳[q-oam-app-activity-9](Ps/pC_qoamappactivity9.md)<br> ↳[q-oam-app-activity-11](Ps/pC_qoamappactivity11.md)<br> ↳[q-oam-app-activity-8](Ps/pC_qoamappactivity8.md)<br> ↳[q-oam-app-activity-12](Ps/pC_qoamappactivity12.md)<br> ↳[q-oam-app-activity-3](Ps/pC_qoamappactivity3.md)<br> ↳[q-oam-app-activity-2](Ps/pC_qoamappactivity2.md)<br><br> physical-access<br> ↳[oracle-access-manager](Ps/pC_oracleaccessmanager.md)<br> | T1078 - Valid Accounts<br>T1133 - External Remote Services<br>    | [<ul><li>31 Rules</li></ul><ul><li>15 Models</li></ul>](RM/r_m_oracle_access_manager_Abnormal_Authentication_&_Access.md) |
|    [Account Manipulation](../../../UseCases/uc_account_manipulation.md)    |  app-activity<br> ↳[q-oam-app-login](Ps/pC_qoamapplogin.md)<br> ↳[s-oam-app-login](Ps/pC_soamapplogin.md)<br><br> app-login<br> ↳[s-oam-app-login-1](Ps/pC_soamapplogin1.md)<br> ↳[s-oam-app-login](Ps/pC_soamapplogin.md)<br><br> authentication-successful<br> ↳[oracle-access-manager](Ps/pC_oracleaccessmanager.md)<br><br> failed-app-login<br> ↳[q-oam-auth-successful](Ps/pC_qoamauthsuccessful.md)<br><br> failed-physical-access<br> ↳[q-oam-app-activity-5](Ps/pC_qoamappactivity5.md)<br> ↳[q-oam-app-activity-4](Ps/pC_qoamappactivity4.md)<br> ↳[q-oam-app-activity-7](Ps/pC_qoamappactivity7.md)<br> ↳[q-oam-app-activity-6](Ps/pC_qoamappactivity6.md)<br> ↳[q-oam-app-activity-10](Ps/pC_qoamappactivity10.md)<br> ↳[q-oam-app-activity-9](Ps/pC_qoamappactivity9.md)<br> ↳[q-oam-app-activity-11](Ps/pC_qoamappactivity11.md)<br> ↳[q-oam-app-activity-8](Ps/pC_qoamappactivity8.md)<br> ↳[q-oam-app-activity-12](Ps/pC_qoamappactivity12.md)<br> ↳[q-oam-app-activity-3](Ps/pC_qoamappactivity3.md)<br> ↳[q-oam-app-activity-2](Ps/pC_qoamappactivity2.md)<br><br> physical-access<br> ↳[oracle-access-manager](Ps/pC_oracleaccessmanager.md)<br> | T1098.002 - Account Manipulation: Exchange Email Delegate Permissions<br> | [<ul><li>3 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_oracle_access_manager_Account_Manipulation.md)    |
[Next Page -->>](2_ds_oracle_access_manager.md)

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                                                                                                   | Execution | Persistence                                                                                                                                                                                                                                                                                                                                 | Privilege Escalation                                                | Defense Evasion                                                     | Credential Access | Discovery | Lateral Movement | Collection                                                                                                                                                            | Command and Control                                                                                                                                                                                                      | Exfiltration                                                                                                                                                           | Impact |
| ------------------------------------------------------------------------------------------------------------------------------------------------ | --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------------- | --------- | ---------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| [External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |           | [External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Account Manipulation](https://attack.mitre.org/techniques/T1098)<br><br>[Account Manipulation: Exchange Email Delegate Permissions](https://attack.mitre.org/techniques/T1098/002)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |                   |           |                  | [Email Collection](https://attack.mitre.org/techniques/T1114)<br><br>[Email Collection: Email Forwarding Rule](https://attack.mitre.org/techniques/T1114/003)<br><br> | [Proxy: Multi-hop Proxy](https://attack.mitre.org/techniques/T1090/003)<br><br>[Application Layer Protocol](https://attack.mitre.org/techniques/T1071)<br><br>[Proxy](https://attack.mitre.org/techniques/T1090)<br><br> | [Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048)<br><br>[Automated Exfiltration](https://attack.mitre.org/techniques/T1020)<br><br> |        |