#### Parser Content
```Java
{
Name = netwrix-ad-member-removed
  DataType = "member-removed"
  Conditions = [ """CEF:0|Netwrix|Active Directory|""", """|Modified group|""", """Removed: """ ]
  Fields = ${NetWrixParserTemplates.netwrix-app-activity-2.Fields}[
    """CEF:0\|Netwrix\|Active Directory\|[^\|]+\|[^\|]+\|({activity}[^\|]+)\|""",
    """cat=group.+?filePath=\\+?([^\\]+\\+)*?({group_name}[^\\]+) start=""",
    """Removed:.+?"{1,20}(\\+)?([^\\\/]+[\\\/]+)*?({target_user}[^\\\/]+?)(;|$|")""",
    """Group Type: "{1,20}({group_type}[^"]+)"{1,20}""",
  ]
}
```