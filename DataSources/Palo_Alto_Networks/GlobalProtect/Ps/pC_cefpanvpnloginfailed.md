#### Parser Content
```Java
{
Name = cef-pan-vpn-login-failed
  Vendor = Palo Alto Networks
  Product = GlobalProtect
  Lms = ArcSight
  DataType = "failed-vpn-login"
  TimeFormat = "epoch"
  Conditions = [ """|Palo Alto Networks|""", """|globalprotect""", """GlobalProtect gateway user login failed""" ]
  Fields = [
    """\Wrt=({time}\d{1,100})""",
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[^\s]{1,2000})""",
    """\Wdvchost=({host}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """Login from:\s{0,100}({src_ip}[a-fA-F\d.:]{1,2000})""",
    """User name:\s{1,100}({user}[\w.'\-\\$]{1,2000})""",
    """User name:\s{1,100}({user_email}[^@\s]{1,2000}@[^\s,]{1,2000}),""",
    """Client OS( version)?:\s{1,100}({os}[^":]{1,2000})(,|\.)""",
    """error:\s{1,100}({failure_reason}[^":]{1,2000})(,|\.)"""
  ]
}
```