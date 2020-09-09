#### Parser Content
```Java
{
Name = netwrix-app-activity-5
  Conditions = [ """CEF:0|Netwrix|Self-audit|""" ]
  Fields = ${NetWrixParserTemplates.netwrix-app-activity-2.Fields}[
    """CEF:0\|Netwrix\|Self-audit\|[^\|]+\|[^\|]+\|({activity}[^\|]+)\|""",
    """cat=({object_type}.+?) \w+=.+?filePath=({object}.+?) \w+=""",
  ]
}
```