#### Parser Content
```Java
{
Name = s-cyberark-activity-4
  DataType = "remote-logon"
  Conditions = [ """|PSM Connect|""", """|Operating System|""" ]
  Fields = ${CyberArkParserTemplates.cyberark-events-1.Fields} [
    """({time}\d+-\d+-\d+T\d+:\d+:\d+Z)\s+({host}[^\s]+)\s+\|({user}[^\|]+)"""  
  ]
  
 }
```