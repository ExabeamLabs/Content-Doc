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
    """exabeam_host=([^=]+@\s{0,100})?({host}[^\s]+)""",
    """\Wdvchost=({host}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """Login from:\s{0,100}({src_ip}[a-fA-F\d.:]+)""",
    """User name:\s{1,100}({user}[\w.'\-\\$]+)""",
    """User name:\s{1,100}({user_email}[^@\s]+@[^\s,]+),""",
    """Client OS( version)?:\s{1,100}({os}[^":]+)(,|\.)""",
    """error:\s{1,100}({failure_reason}[^":]+)(,|\.)"""
  ]
}
```