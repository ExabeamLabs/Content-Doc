#### Parser Content
```Java
{
Name = s-cyberark-activity-7
  DataType = "app-activity"
  Conditions = [ """|Store password|""", """|PSMUnmanagedSessionAccounts|""" ]
  Fields = ${CyberArkParserTemplates.cyberark-events-1.Fields} [
    """({time}\d+-\d+-\d+T\d+:\d+:\d+Z)\s+({host}[^\s]+)\s+\|[^\|]+\|({activity}[^\|]+)\|({event_code}[^\|]+)\|""",
    ]
 }
```