Vendor: Amazon
==============
### Product: [AWS CloudTrail](../ds_amazon_aws_cloudtrail.md)
### Use-Case: [Privilege Escalation](../../../../UseCases/uc_privilege_escalation.md)

| Rules | Models | MITRE ATT&CK® TTPs | Event Types | Parsers |
|:-----:|:------:|:------------------:|:-----------:|:-------:|
|   9   |   6    |         2          |      7      |    7    |

| Event Type    | Rules    | Models    |
| ---- | ---- | ---- |
| app-activity    | <b>T1098.002 - Account Manipulation: Exchange Email Delegate Permissions</b><br> ↳ <b>EM-InB-Ex</b>: A user has been given mailbox permissions for an executive user<br> ↳ <b>EM-InB-Perm-N-F</b>: First time a user has given mailbox permissions on another mailbox that is not their own<br> ↳ <b>EM-InB-Perm-N-A</b>: Abnormal for user to give mailbox permissions |  • <b>EM-InB-Perm-N</b>: Models users who give mailbox permissions    |
| aws-instance-creds-read | <b>TA0004 - TA0004</b><br> ↳ <b>AWS-UserGetPasswordData-Org-F</b>: First time AWS instance administrator password extracted by user    |  • <b>AWS-UserGetPasswordData-Org</b>: AWS instance password retrieval    |
| aws-policy-attach       | <b>TA0004 - TA0004</b><br> ↳ <b>AWS-AdminPolicyAttach</b>: A critical policy with admin permissions was attached to an identity in AWS    |    |
| aws-policy-write        | <b>TA0004 - TA0004</b><br> ↳ <b>AWS-AdminPolicy</b>: A critical policy with admin permissions was created in AWS<br> ↳ <b>AWS-UserCreatePolicyAdmin-Org-F</b>: First time this user created an administrative policy in AWS    |  • <b>AWS-UserCreatePolicyAdmin-Org</b>: AWS users who created a critical policy    |
| aws-role-assume         | <b>TA0004 - TA0004</b><br> ↳ <b>AWS-AssumedRoles-User-F</b>: First time this user assumed this role in AWS<br> ↳ <b>AWS-AssumingUsers-Role-F</b>: First time this role was assumed by this user in AWS    |  • <b>AWS-AssumingUsers-Role</b>: AWS user that assumed a role<br> • <b>AWS-AssumedRoles-User</b>: AWS roles the user assumed/switched |
| aws-role-assumepolicy   | <b>TA0004 - TA0004</b><br> ↳ <b>AWS-RolePublicPolicy-Org-F</b>: First time this role was made public in AWS    |  • <b>AWS-RolePublicPolicy-Org</b>: AWS roles who were given a public assume policy    |
| aws-role-switch         | <b>TA0004 - TA0004</b><br> ↳ <b>AWS-AssumedRoles-User-F</b>: First time this user assumed this role in AWS<br> ↳ <b>AWS-AssumingUsers-Role-F</b>: First time this role was assumed by this user in AWS    |  • <b>AWS-AssumingUsers-Role</b>: AWS user that assumed a role<br> • <b>AWS-AssumedRoles-User</b>: AWS roles the user assumed/switched |