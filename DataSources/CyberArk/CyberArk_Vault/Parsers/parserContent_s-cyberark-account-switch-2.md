#### Parser Content
```Java
{
Name = s-cyberark-account-switch-2
  DataType = "account-switch"
  Conditions = [ """|Retrieve password|""", """PSMConnect|""" ]
  Fields = ${CyberArkParserTemplates.cyberark-events-1.Fields} [
    """({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}Z)\s{1,100}({host}[^\s]+)\s{1,100}\|({user}[^\|]+)"""
    """Retrieve password\|([^\|]+\|){1}({src_ip}[A-Za-z0-9.:]+)""",
    ]
 }
```