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
    """,globalprotect,\d+,({time}\d\d\d\d\/\d\d\/\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=([^=]+@\s*)?({host}[^\s]+)""",
    """Login from:\s*({src_ip}[a-fA-F\d.:]+)""",
    """User name:\s*({user}[^\s,"]+?)\.?(\s|,|"|$)""",
    """User name:\s+({user_email}[^@\s]+@[^\s,]+),""",
    """Reason:\s+(Authentication failed:)?\s*({failure_reason}[^":]+?)\s*(,|\.)""",
    """Source region:\s*({src_country}[^,]+)"""
  ]
}
```