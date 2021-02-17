#### Parser Content
```Java
{
Name = s-cyberark-account-switch-2
  DataType = "account-switch"
  Conditions = [ """|Retrieve password|""", """PSMConnect|""" ]
  Fields = ${CyberArkParserTemplates.cyberark-events-1.Fields} [
    """({time}\d+-\d+-\d+T\d+:\d+:\d+Z)\s+({host}[^\s]+)\s+\|({user}[^\|]+)"""
    """Retrieve password\|([^\|]+\|){1}({src_ip}[A-Za-z0-9.:]+)""",
    ]
 }
```