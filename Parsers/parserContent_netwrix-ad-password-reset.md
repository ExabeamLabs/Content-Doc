#### Parser Content
```Java
{
Name = netwrix-ad-password-reset
  DataType = "windows-password-reset"
  Conditions = [ """CEF:0|Netwrix|Active Directory|""", """msg=Administrative Password Reset""" ]
  Fields = ${NetWrixParserTemplates.netwrix-app-activity-2.Fields}[
    """CEF:0\|Netwrix\|Active Directory\|[^\|]+\|[^\|]+\|({activity}[^\|]+)\|""",
    """cat=user.+?filePath=\\*?([^\\]+\\+)*?({target_user}[^\\]+) start=""",
  ]
}
```