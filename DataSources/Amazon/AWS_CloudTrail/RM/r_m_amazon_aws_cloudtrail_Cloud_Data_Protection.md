Vendor: Amazon
==============
### Product: [AWS CloudTrail](../ds_amazon_aws_cloudtrail.md)
### Use-Case: [Cloud Data Protection](../../../../UseCases/uc_cloud_data_protection.md)

| Rules | Models | MITRE ATT&CK® TTPs | Event Types | Parsers |
|:-----:|:------:|:------------------:|:-----------:|:-------:|
|  12   |   7    |         2          |      8      |    8    |

| Event Type    | Rules    | Models    |
| ---- | ---- | ---- |
| aws-policy-attach     | <b>TA0004 - TA0004</b><br> ↳ <b>AWS-UserAddIdentityPolicy-Org-F</b>: First time policy attachment to an identity for this user<br> ↳ <b>AWS-UserAddIdentityPolicyGlobal-Org-F</b>: First time critical (global) policy attachment for user<br> ↳ <b>AWS-UserAddIdentityPolicyCritical-Org-F</b>: First time critical policy added by user    |  • <b>AWS-UserAddIdentityPolicy-Org</b>: AWS - users who added or attached identity policies in the organization    |
| aws-policy-list       | <b>TA0007 - TA0007</b><br> ↳ <b>AWS-UserPermEnum-Org-F</b>: First time permissions enumeration for user    |  • <b>AWS-UserPermEnum-Org</b>: AWS - permissions enumerations for user in the organization    |
| aws-policy-setversion | <b>TA0004 - TA0004</b><br> ↳ <b>AWS-UserSetDefaultPolicyVersion-Org-F</b>: First time default policy version rollback for user    |  • <b>AWS-UserSetDefaultPolicyVersion-Org</b>: AWS - users who rolled back a policy version in the organization    |
| aws-policy-write      | <b>TA0004 - TA0004</b><br> ↳ <b>AWS-CriticalPolicy</b>: A critical policy was created in AWS<br> ↳ <b>AWS-UserAddIdentityPolicy-Org-F</b>: First time policy attachment to an identity for this user<br> ↳ <b>AWS-UserAddIdentityPolicyGlobal-Org-F</b>: First time critical (global) policy attachment for user<br> ↳ <b>AWS-UserAddIdentityPolicyCritical-Org-F</b>: First time critical policy added by user<br> ↳ <b>AWS-UserCreatePolicy-Org-F</b>: First time policy creation for user<br> ↳ <b>AWS-UserCreatePolicyCritical-Org-F</b>: First time critical policy creation for user<br> ↳ <b>AWS-UserCreatePolicyCriticalGlobal-Org-F</b>: First time critical (global) policy creation for user |  • <b>AWS-UserCreatePolicy-Org</b>: AWS - users who created a policy in the organization<br> • <b>AWS-UserAddIdentityPolicy-Org</b>: AWS - users who added or attached identity policies in the organization |
| aws-role-assume       | <b>TA0004 - TA0004</b><br> ↳ <b>AWS-UserAssumeRole-Org-F</b>: First time this user assumed a role in AWS    |  • <b>AWS-UserAssumeRole-Org</b>: AWS - users who assumed/switched roles in the organization    |
| aws-role-assumepolicy | <b>TA0004 - TA0004</b><br> ↳ <b>AWS-UserModifyAssumeRole-Org-F</b>: First time this user modified who can assume a role in AWS    |  • <b>AWS-UserModifyAssumeRole-Org</b>: AWS - users who modified assume role policies in the organization    |
| aws-role-switch       | <b>TA0004 - TA0004</b><br> ↳ <b>AWS-UserAssumeRole-Org-F</b>: First time this user assumed a role in AWS    |  • <b>AWS-UserAssumeRole-Org</b>: AWS - users who assumed/switched roles in the organization    |
| aws-role-write        | <b>TA0004 - TA0004</b><br> ↳ <b>AWS-UserCreateRole-Org-F</b>: First time this user has performed role creation.    |  • <b>AWS-UserCreateRole-Org</b>: AWS - users who created roles in the organization    |