#### Parser Content
```Java
{
Name = s-cyberark-activity-1
  DataType = "remote-logon"
  Conditions = [ """|Window Title|""", """|Operating System|""" ]
  Fields = ${CyberArkParserTemplates.cyberark-events-1.Fields} [
    """({time}\d+-\d+-\d+T\d+:\d+:\d+Z)\s+({host}[^\s]+)\s+\|({user}[^\|]+)"""
    ]
 }
```