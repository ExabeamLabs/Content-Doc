#### Parser Content
```Java
{
Name = s-cyberark-failed-logon-1
  DataType = "failed-logon"
  Conditions = [ """|Window Title|""","""Command=FAILED TO INITIATE WINDOWS SESSION AUDIT""" ]
  Fields = ${CyberArkParserTemplates.cyberark-events-1.Fields} [
    """({time}\d+-\d+-\d+T\d+:\d+:\d+Z)\s+({host}[^\s]+)\s+\|({user}[^\|]+)"""
    ]
 }
```