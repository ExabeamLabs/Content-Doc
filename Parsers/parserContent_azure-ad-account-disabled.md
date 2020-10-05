#### Parser Content
```Java
{
Name = azure-ad-account-disabled
  DataType = "account-disabled"
  Conditions = [ """Microsoft.aadiam""", """Disable account""", """tenantId":""""]
  Fields = ${MSParserTemplates.azure-ad-activity.Fields} [
    """({event_name}Disable account)""",
    """targetResources":.+?userPrincipalName":"({target_user}[^",]+)""",
    """targetResources":.+?id":"({user_sid}[^",]+)"""
  ]
}
```