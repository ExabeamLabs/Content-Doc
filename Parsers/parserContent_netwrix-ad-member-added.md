#### Parser Content
```Java
{
Name = netwrix-ad-member-added
  DataType = "member-added"
  Conditions = [ """CEF:0|Netwrix|Active Directory|""", """|Added group|""" ]
  Fields = ${NetWrixParserTemplates.netwrix-app-activity-2.Fields}[
    """CEF:0\|Netwrix\|Active Directory\|[^\|]+\|[^\|]+\|({activity}[^\|]+)\|""",
    """cat=group.+?filePath=\\+?([^\\]+\\+)*?({group_name}[^\\]+) start=""",
    """Added:.+?"+(\\+)?([^\\\/]+[\\\/]+)*?({target_user}[^\\\/]+?)(;|$|")""",
    """Group Type: "+({group_type}[^"]+)"+""",
  ]
}
```