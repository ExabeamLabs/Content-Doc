#### Parser Content
```Java
{
Name = pan-vpn-login-failed
  Vendor = Palo Alto Networks
  Product = GlobalProtect
  Lms = Direct
  DataType = "failed-vpn-login"
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [ """,globalprotectgateway-regist-fail,""", """GlobalProtect gateway user login failed""" ]
  Fields = [
    """({host}[\w.\-]+)\s+\d+,({time}\d\d\d\d\/\d\d\/\d\d \d\d:\d\d:\d\d),[^,]*,SYSTEM,globalprotect,""",
    """Login from:\s*({src_ip}[a-fA-F\d.:]+)""",
    """User name:\s+({user}[^,]+)""",
    """User name:\s+({user_email}[^@\s]+@[^\s,]+),""",
    """Client OS( version)?:\s+({os}[^":]+?)\s*(,|\.)""",
    """error:\s+({failure_reason}[^":]+?)(,|\.)"""
  ]
}
```