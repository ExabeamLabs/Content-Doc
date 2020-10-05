#### Parser Content
```Java
{
Name = azure-ad-member-removed
  DataType = "member-removed"
  Conditions = [ """Microsoft.aadiam""", """Remove member from group""", """tenantId":""""]
  Fields = ${MSParserTemplates.azure-ad-activity.Fields} [
    """({event_name}Remove member from group)""",
    """targetResources":.+?Group\.DisplayName.+?newValue":"\\*"({group_name}[^\\"]+)""",
    """targetResources":.+?id":"({account_id}[^",]+)"""
  ]
}
```