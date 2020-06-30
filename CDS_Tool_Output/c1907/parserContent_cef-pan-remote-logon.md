#### Parser Content
```Java
{
Name = cef-pan-remote-logon
  Vendor = Palo Alto Networks
  Product = GlobalProtect
  Lms = ArcSight
  DataType = "remote-logon"
  TimeFormat = "epoch"
  Conditions = [ """|Palo Alto Networks|""", """|globalprotect""", """GlobalProtect portal user login succeeded""" ]
  Fields = [
    """\Wrt=({time}\d+)""",
    """exabeam_host=([^=]+@\s*)?({host}[^\s]+)""",
    """\Wdvchost=({host}.+?)(\s+\w+=|\s*$)""",
    """Login from:\s*({src_ip}[a-fA-F\d.:]+)""",
    """User name:\s+({user}[\w.'\-\\$]+)""",
    """User name:\s+({user_email}[^@\s]+@[^\s,]+),""",
    """Client OS( version)?:\s+({os}[^":]+)(,|\.)"""
  ]
}
```