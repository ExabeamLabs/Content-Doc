#### Parser Content
```Java
{
Name = s-cyberark-activity-1
  DataType = "remote-logon"
  Conditions = [ """|Window Title|""", """|Operating System|""" ]
  Fields = ${CyberArkParserTemplates.cyberark-events-1.Fields} [
    """({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}Z)\s{1,100}({host}[^\s]{1,2000})\s{1,100}\|({user}[^\|]{1,2000})"""
    ]
 }
```