#### Parser Content
```Java
{
Name = s-cyberark-activity-5
  DataType = "remote-logon"
  Conditions = [ """|Keystroke logging|""", """|Operating System|""" ]
  Fields = ${CyberArkParserTemplates.cyberark-events-1.Fields} [
    """({time}\d+-\d+-\d+T\d+:\d+:\d+Z)\s+({host}[^\s]+)\s+\|({user}[^\|]+)"""
    ]
 }
```