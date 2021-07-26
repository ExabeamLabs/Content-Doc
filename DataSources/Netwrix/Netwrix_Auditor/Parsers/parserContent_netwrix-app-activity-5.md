#### Parser Content
```Java
{
Name = netwrix-app-activity-5
  Conditions = [ """CEF:0|Netwrix|Self-audit|""" ]
  Fields = ${NetWrixParserTemplates.netwrix-app-activity-2.Fields}[
    """CEF:0\|Netwrix\|Self-audit\|[^\|]{1,2000}\|[^\|]{1,2000}\|({activity}[^\|]{1,2000})\|""",
    """cat=({object_type}.+?) \w+=.+?filePath=({object}.+?) \w+=""",
  ]
}
```