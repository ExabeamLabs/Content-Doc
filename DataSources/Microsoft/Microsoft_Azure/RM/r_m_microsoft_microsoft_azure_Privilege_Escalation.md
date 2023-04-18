Vendor: Microsoft
=================
### Product: [Microsoft Azure](../ds_microsoft_microsoft_azure.md)
### Use-Case: [Privilege Escalation](../../../../UseCases/uc_privilege_escalation.md)

| Rules | Models | MITRE ATT&CK® TTPs | Event Types | Parsers |
|:-----:|:------:|:------------------:|:-----------:|:-------:|
|   2   |   2    |         1          |      2      |    2    |

| Event Type        | Rules    | Models    |
| ---- | ---- | ---- |
| azure-role-assign | <b>TA0004 - TA0004</b><br> ↳ <b>Azure-UserRoleAssign-Org-F</b>: First time Azure role assignment for user    |  • <b>Azure-UserRoleAssign-Org</b>: Azure - users who created IAM role assignments    |
| azure-role-write  | <b>TA0004 - TA0004</b><br> ↳ <b>Azure-UserRoleDefinitionWrite-Org-F</b>: First time Azure role definition modification for user |  • <b>Azure-UserRoleDefinitionWrite-Org</b>: Azure - Users who created/modified IAM role definitions |