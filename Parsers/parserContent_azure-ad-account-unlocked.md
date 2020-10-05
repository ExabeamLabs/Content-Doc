#### Parser Content
```Java
{
Name = azure-ad-account-unlocked
  DataType = "account-unlocked"
  Conditions = [ """Microsoft.aadiam""", """Unlock user account (self-service)""", """tenantId":""""]
  Fields = ${MSParserTemplates.azure-ad-activity.Fields} [
    """({event_name}Unlock user account)""",
    """targetResources":.+?userPrincipalName":"({target_user}[^",]+)""",
    """targetResources":.+?id":"({user_sid}[^",]+)"""
  ]
}
```