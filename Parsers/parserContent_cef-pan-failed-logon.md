#### Parser Content
```Java
{
Name = cef-pan-failed-logon
  Vendor = Palo Alto Networks
  Product = GlobalProtect
  Lms = ArcSight
  DataType = "failed-logon"
  TimeFormat = "epoch"
  Conditions = [ """|Palo Alto Networks|""", """|globalprotect""", """GlobalProtect portal user login failed""" ]
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