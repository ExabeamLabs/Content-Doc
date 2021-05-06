#### Parser Content
```Java
{
Name = pan-auth-successful
  Vendor = Palo Alto Networks
  Product = GlobalProtect
  Lms = Direct
  DataType = "authentication-successful"
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [ """,SYSTEM,auth,""", """,auth-success,""" ]
  Fields = [
    """SYSTEM,auth,[^,]+,({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z),""",
    """:\d\d:\d\d\s+({host}[\w.-]+)\s""",
    """\w+\s+\d+\s+\d+:\d+:\d+\s+({host}[\w\-.]+)\s+\d+,({time}\d+\/\d+\/\d+\s+\d+:\d+:\d+),""",
    """,auth-success,({auth_method}[^,]+)""",
    """"authenticated for user '({user}[^\s']+)""",
    """From:\s*(({src_ip}[A-Fa-f:\d.]+?)|({src_host}.+?))\.?"""",
    """({event_name}auth-success)""",
    """auth-success,([^,]*,){5}"?({additional_info}[^,']+?)\s'"""
  ]
}
```