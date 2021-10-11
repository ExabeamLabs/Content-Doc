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
    """({host}[\w.\-]{1,2000})\s{1,100}\d{1,100},({time}\d\d\d\d\/\d\d\/\d\d \d\d:\d\d:\d\d),[^,]{0,2000},SYSTEM,globalprotect,""",
    """Login from:\s{0,100}({src_ip}[a-fA-F\d.:]{1,2000})""",
    """User name:\s{1,100}({user}[^,]{1,2000})""",
    """User name:\s{1,100}({user_email}[^@\s]{1,2000}@[^\s,]{1,2000}),""",
    """Client OS( version)?:\s{1,100}({os}[^":]{1,2000}?)\s{0,100}(,|\.)""",
    """error:\s{1,100}({failure_reason}[^":]{1,2000}?)(,|\.)"""
  ]
}
```