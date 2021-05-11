#### Parser Content
```Java
{
Name = s-cyberark-activity-6
  DataType = "app-activity"
  Conditions = [ """|Use Password|""", """|Operating System|""" ]
  Fields = ${CyberArkParserTemplates.cyberark-events-1.Fields} [
    """({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}Z)\s{1,100}({host}[^\s]+)\s{1,100}\|({user}[^\|]+)\|[^\|]+\|({activity}[^\|]+)"""
    ]
 }
```