#### Parser Content
```Java
{
Name = s-cyberark-account-switch-3
  DataType = "account-switch"
  Conditions = [ """|Retrieve password|""", """PSMAdminConnect|""" ]
  Fields = ${CyberArkParserTemplates.cyberark-events-1.Fields} [
    """({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}Z)\s{1,100}({host}[^\s]{1,2000})\s{1,100}\|({user}[^\|]{1,2000})"""
    """Retrieve password\|([^\|]{1,2000}\|){1}({src_ip}[A-Za-z0-9.:]{1,2000})""",
    ]
 }
```