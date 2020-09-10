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
    """\Wrt=({time}\d+)""",
    """exabeam_host=([^=]+@\s*)?({host}[^\s]+)""",
    """\Wdvchost=({host}.+?)(\s+\w+=|\s*$)""",
    """Login from:\s*({src_ip}[a-fA-F\d.:]+)""",
    """User name:\s+({user}[\w.'\-\\$]+)""",
    """User name:\s+({user_email}[^@\s]+@[^\s,]+),""",
    """Client OS( version)?:\s+({os}[^":]+)(,|\.)""",
    """error:\s+({failure_reason}[^":]+)(,|\.)"""
  ]
}
```