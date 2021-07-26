#### Parser Content
```Java
{
Name = s-cyberark-failed-logon-1
  DataType = "failed-logon"
  Conditions = [ """|Window Title|""","""Command=FAILED TO INITIATE WINDOWS SESSION AUDIT""" ]
  Fields = ${CyberArkParserTemplates.cyberark-events-1.Fields} [
    """({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}Z)\s{1,100}({host}[^\s]{1,2000})\s{1,100}\|({user}[^\|]{1,2000})"""
    ]
 }
```