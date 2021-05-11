#### Parser Content
```Java
{
Name = cef-pan-auth-successful
  Vendor = Palo Alto Networks
  Product = GlobalProtect
  Lms = ArcSight
  DataType = "authentication-successful"
  TimeFormat = "epoch"
  Conditions = [ """|Palo Alto Networks|""", """|globalprotect""", """user authentication succeeded""" ]
  Fields = [
    """\Wrt=({time}\d{1,100})""",
    """\Wrt=({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=([^=]+@\s{0,100})?({host}[^\s]+)""",
    """\Wdvchost=({host}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """Login from:\s{0,100}({src_ip}[a-fA-F\d.:]+)""",
    """User name:\s{1,100}(({domain}[^\\]+)\\+)?({user}[\w.'\-\\$]+?)\.?(\s|,|"|$)""",
    """User name:\s{1,100}({user_email}[^@\s]+@[^\s,]+),""",
    """Client OS( version)?:\s{1,100}({os}[^":]+)(,|\.)"""
  ]
}
```