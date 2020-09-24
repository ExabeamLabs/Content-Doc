#### Parser Content
```Java
{
Name = azure-ad-account-password-change-1
  DataType = "password-change"
  Conditions = [ """Microsoft.aadiam""", """Self-service password reset""", """tenantId":""""]
  Fields = ${MSParserTemplates.azure-ad-activity.Fields} [
    """({event_name}Self-service password reset)""",
    """targetResources":.+?userPrincipalName":"({target_user}[^",]+)""",
    """targetResources":.+?id":"({user_sid}[^",]+)"""
  ]
}
```