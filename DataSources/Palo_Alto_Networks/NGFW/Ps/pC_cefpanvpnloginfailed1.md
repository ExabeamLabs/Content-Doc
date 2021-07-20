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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[^\s]{1,2000})""",
    """\Wdvchost=({host}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """Login from:\s{0,100}({src_ip}[a-fA-F\d.:]{1,2000})""",
    """User name:\s{1,100}(({domain}[^\\]{1,2000})\\+)?({user}[\w.'\-\\$]{1,2000}?)\.?(\s|,|"|$)""",
    """User name:\s{1,100}({user_email}[^@\s]{1,2000}@[^\s,]{1,2000}),""",
    """Client OS( version)?:\s{1,100}({os}[^":]{1,2000})(,|\.)"""
  ]

```