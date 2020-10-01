#### Parser Content
```Java
{
Name = netwrix-ad-account-lockout
  DataType = "windows-account-lockout"
  Conditions = [ """CEF:0|Netwrix|Active Directory|""", """msg=User Account Locked Out """ ]
  Fields = ${NetWrixParserTemplates.netwrix-app-activity-2.Fields}[
    """CEF:0\|Netwrix\|Active Directory\|[^\|]+\|[^\|]+\|({activity}[^\|]+)\|""",
    """cat=user.+?filePath=\\+?([^\\]+\\+)*?({target_user}[^\\]+) start=""",
  ]
}
```