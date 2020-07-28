#### Parser Content
```Java
{
Name = s-cyberark-activity
  DataType = "remote-logon"
  Conditions = [ """|Window Title|""", """|PSMSecureConnect|""" ]
  Fields = ${CyberArkParserTemplates.cyberark-events-1.Fields} [
    """({time}\d+-\d+-\d+T\d+:\d+:\d+Z)\s+({host}[^\s]+)\s+\|({user}[^\|]+)"""
    ]
 }
```