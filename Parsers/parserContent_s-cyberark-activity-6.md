#### Parser Content
```Java
{
Name = s-cyberark-activity-6
  DataType = "app-activity"
  Conditions = [ """|Use Password|""", """|Operating System|""" ]
  Fields = ${CyberArkParserTemplates.cyberark-events-1.Fields} [
    """({time}\d+-\d+-\d+T\d+:\d+:\d+Z)\s+({host}[^\s]+)\s+\|({user}[^\|]+)\|[^\|]+\|({activity}[^\|]+)"""
    ]
 }
```