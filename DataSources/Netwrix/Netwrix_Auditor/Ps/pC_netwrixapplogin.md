#### Parser Content
```Java
{
Name = netwrix-app-login
  DataType = "app-login"
  Conditions = [ """CEF:0|Netwrix|""", """|Successful Logon|""" ]
  Fields = ${NetWrixParserTemplates.netwrix-app-activity-2.Fields}[
    """CEF:0\|Netwrix\|(AD FS|Logon Activity|Self-audit)\|[^\|]{1,2000}\|[^\|]{1,2000}\|({activity}[^\|]{1,2000})\|""",
  ]
}
```