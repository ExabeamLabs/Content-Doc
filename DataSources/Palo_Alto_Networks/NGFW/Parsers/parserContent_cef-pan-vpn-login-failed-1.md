#### Parser Content
```Java
{
Name = cef-pan-vpn-login-failed-1
  DataType = "failed-vpn-login"
  Conditions = [ """CEF:""", """|Palo Alto Networks|""", """globalprotect""", """GlobalProtect gateway user login failed""" ]
  Fields = ${PaloAltoParserTemplates.cef-pan-vpn-event.Fields}[
    """\Wreason=({failure_reason}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
  ]
}
cef-pan-vpn-event = {
  Vendor = Palo Alto Networks
  Product = GlobalProtect
  Lms = ArcSight
  TimeFormat = "epoch"
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

```