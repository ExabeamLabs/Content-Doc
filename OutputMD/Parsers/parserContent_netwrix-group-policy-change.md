#### Parser Content
```Java
{
Name = netwrix-group-policy-change
  DataType = "ds-access"
  Conditions = [ """CEF:0|Netwrix|Group Policy|""" ]
  Fields = ${NetWrixParserTemplates.netwrix-app-activity-2.Fields}[
    """CEF:0\|Netwrix\|Active Directory\|[^\|]+\|[^\|]+\|({activity}[^\|]+)\|""",
    """cat=GroupPolicy.+?filePath=({policy}.+?) start=""",
  ]
}
```