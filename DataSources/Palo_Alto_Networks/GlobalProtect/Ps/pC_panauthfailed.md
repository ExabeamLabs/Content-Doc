#### Parser Content
```Java
{
Name = pan-auth-failed
  Vendor = Palo Alto Networks
  Product = GlobalProtect
  Lms = Direct
  DataType = "authentication-failed"
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [ """,globalprotect,""", """user authentication failed""" ]
  Fields = [
    """,globalprotect,\d{1,100},({time}\d\d\d\d\/\d\d\/\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[^\s]{1,2000})""",
    """Login from:\s{0,100}({src_ip}[a-fA-F\d.:]{1,2000})""",
    """User name:\s{0,100}({user}[^\s,"]{1,2000}?)\.?(\s|,|"|$)""",
    """User name:\s{1,100}({user_email}[^@\s]{1,2000}@[^\s,]{1,2000}),""",
    """Reason:\s{1,100}(Authentication failed:)?\s{0,100}({failure_reason}[^":]{1,2000}?)\s{0,100}(,|\.)""",
    """Source region:\s{0,100}({src_country}[^,]{1,2000})"""
  ]
}
```