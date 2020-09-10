#### Parser Content
```Java
{
Name = pan-azure-auth-attempt
  Vendor = Palo Alto Networks
  Product = GlobalProtect
  Lms = Direct
  DataType = "authentication-attempt"
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [ """,SYSTEM,auth,""", """AUTH_PROFILE_AZURE""" ]
  Fields = [
    """\w+\s+\d+\s+\d+:\d+:\d+\s+({host}[\w\-.]+)\s+\d+,({time}\d+\/\d+\/\d+\s+\d+:\d+:\d+),""",
    """(c|C)lient '({src_ip}[A-Fa-f:\d.]+)""",
    """for user\s*'({user_email}[^']+)"""
    ]
}
```