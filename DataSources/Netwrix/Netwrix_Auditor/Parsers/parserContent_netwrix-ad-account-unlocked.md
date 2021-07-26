#### Parser Content
```Java
{
Name = netwrix-ad-account-unlocked
  DataType = "windows-account-enabled"
  Conditions = [ """CEF:0|Netwrix|Active Directory|""", """|Modified user|""", """msg=User Account Unlocked""" ]
  Fields = ${NetWrixParserTemplates.netwrix-app-activity-2.Fields}[
    """CEF:0\|Netwrix\|Active Directory\|[^\|]{1,2000}\|[^\|]{1,2000}\|({activity}[^\|]{1,2000})\|""",
    """cat=user.+?filePath=\\+?([^\\]{1,2000}\\+)*?({target_user}[^\\]{1,2000}) start=""",
  ]
}
```