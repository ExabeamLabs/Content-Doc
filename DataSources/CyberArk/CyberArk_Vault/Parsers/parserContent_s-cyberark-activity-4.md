#### Parser Content
```Java
{
Name = s-cyberark-activity-4
  DataType = "remote-logon"
  Conditions = [ """|PSM Connect|""", """|Operating System|""" ]
  Fields = ${CyberArkParserTemplates.cyberark-events-1.Fields} [
    """({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}Z)\s{1,100}({host}[^\s]{1,2000})\s{1,100}\|({user}[^\|]{1,2000})"""  
  ]
  
 }
```