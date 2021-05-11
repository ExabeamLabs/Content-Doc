#### Parser Content
```Java
{
Name = netwrix-ad-member-added-2
  DataType = "member-added"
  Conditions = [ """CEF:0|Netwrix|Active Directory|""", """|Modified group|""", """Added: """ ]
  Fields = ${NetWrixParserTemplates.netwrix-app-activity-2.Fields}[
    """CEF:0\|Netwrix\|Active Directory\|[^\|]+\|[^\|]+\|({activity}[^\|]+)\|""",
    """cat=group.+?filePath=\\+?([^\\]+\\+)*?({group_name}[^\\]+) start=""",
    """Added:.+?"{1,20}(\\+)?([^\\\/]+[\\\/]+)*?({target_user}[^\\\/]+?)(;|$|")""",
    """Group Type: "{1,20}({group_type}[^"]+)"{1,20}""",
  ]
}
```