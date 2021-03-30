#### Parser Content
```Java
{
Name = cef-pan-vpn-login-failed-1
  DataType = "failed-vpn-login"
  Conditions = [ """CEF:""", """|Palo Alto Networks|""", """globalprotect""", """GlobalProtect gateway user login failed""" ]
  Fields = ${PaloAltoParserTemplates.cef-pan-vpn-event.Fields}[
    """\Wreason=({failure_reason}.+?)(\s+\w+=|\s*$)""",
  ]
}
cef-pan-vpn-event = {
  Vendor = Palo Alto Networks
  Product = GlobalProtect
  Lms = ArcSight
  TimeFormat = "epoch"
  Fields = [
    """\Wrt=({time}\d+)""",
    """\Wrt=({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=([^=]+@\s*)?({host}[^\s]+)""",
    """\Wdvchost=({host}.+?)(\s+\w+=|\s*$)""",
    """Login from:\s*({src_ip}[a-fA-F\d.:]+)""",
    """User name:\s+(({domain}[^\\]+)\\+)?({user}[\w.'\-\\$]+?)\.?(\s|,|"|$)""",
    """User name:\s+({user_email}[^@\s]+@[^\s,]+),""",
    """Client OS( version)?:\s+({os}[^":]+)(,|\.)"""
  ]

```