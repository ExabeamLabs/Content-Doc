#### Parser Content
```Java
{
Name = netwrix-ad-member-added-2
  DataType = "member-added"
  Conditions = [ """CEF:0|Netwrix|Active Directory|""", """|Modified group|""", """Added: """ ]
  Fields = ${NetWrixParserTemplates.netwrix-app-activity-2.Fields}[
    """CEF:0\|Netwrix\|Active Directory\|[^\|]{1,2000}\|[^\|]{1,2000}\|({activity}[^\|]{1,2000})\|""",
    """cat=group.+?filePath=\\+?([^\\]{1,2000}\\+)*?({group_name}[^\\]{1,2000}) start=""",
    """Added:.+?"{1,20}(\\+)?([^\\\/]{1,2000}[\\\/]{1,2000})*?({target_user}[^\\\/]{1,2000}?)(;|$|")""",
    """Group Type: "{1,20}({group_type}[^"]{1,2000})"{1,20}""",
  ]
}
```