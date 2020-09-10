#### Parser Content
```Java
{
Name = netwrix-ad-account-unlocked
  DataType = "windows-account-enabled"
  Conditions = [ """CEF:0|Netwrix|Active Directory|""", """|Modified user|""", """msg=User Account Unlocked""" ]
  Fields = ${NetWrixParserTemplates.netwrix-app-activity-2.Fields}[
    """CEF:0\|Netwrix\|Active Directory\|[^\|]+\|[^\|]+\|({activity}[^\|]+)\|""",
    """cat=user.+?filePath=\\+?([^\\]+\\+)*?({target_user}[^\\]+) start=""",
  ]
}
```