Vendor: SAP
===========
### Product: [SAP](../ds_sap_sap.md)
### Use-Case: [Privilege Escalation](../../../../UseCases/uc_privilege_escalation.md)

| Rules | Models | MITRE ATT&CK® TTPs | Event Types | Parsers |
|:-----:|:------:|:------------------:|:-----------:|:-------:|
|   7   |   4    |         5          |      4      |    4    |

| Event Type    | Rules    | Models    |
| ---- | ---- | ---- |
| app-activity    | <b>T1098.002 - Account Manipulation: Exchange Email Delegate Permissions</b><br> ↳ <b>EM-InB-Ex</b>: A user has been given mailbox permissions for an executive user<br> ↳ <b>EM-InB-Perm-N-F</b>: First time a user has given mailbox permissions on another mailbox that is not their own<br> ↳ <b>EM-InB-Perm-N-A</b>: Abnormal for user to give mailbox permissions |  • <b>EM-InB-Perm-N</b>: Models users who give mailbox permissions    |
| gcp-role-list    | <b>TA0007 - TA0007</b><br> ↳ <b>GCP-UserRoleList-Org-F</b>: First time role enumeration for user    |  • <b>GCP-UserRoleList-Org</b>: Users who enumerated IAM roles in GCP    |
| gcp-serviceaccount-creds-write | <b>TA0004 - TA0004</b><br> ↳ <b>GCP-UserCreateServiceAccountCreds-Org-F</b>: First time service account key/token creation for user    |  • <b>GCP-UserCreateServiceAccountCreds-Org</b>: Users who created/uploaded service acccount keys and tokens in GCP |
| remote-logon    | <b>T1078 - Valid Accounts</b><br> ↳ <b>AS-PV-UHWoPC</b>: Access to Password Vault managed asset with no password checkout for user<br> ↳ <b>DC18-new</b>: Account switch by new user<br><br><b>T1555.005 - T1555.005</b><br> ↳ <b>AS-PV-UHWoPC</b>: Access to Password Vault managed asset with no password checkout for user    |  • <b>AS-PV-OA</b>: Password retrieval based accounts    |