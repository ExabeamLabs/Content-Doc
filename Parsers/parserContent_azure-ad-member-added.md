#### Parser Content
```Java
{
Name = azure-ad-member-added
  DataType = "member-added"
  Conditions = [ """Microsoft.aadiam""", """Add member to group""", """tenantId":""""]
  Fields = ${MSParserTemplates.azure-ad-activity.Fields} [
    """({event_name}Add member to group)""",
    """targetResources"+:\[\{([^,]+,){3}"+userPrincipalName"+:"+({target_user}[^"]+)"""",
    """targetResources"+:\[\{[^\}]+\}
```