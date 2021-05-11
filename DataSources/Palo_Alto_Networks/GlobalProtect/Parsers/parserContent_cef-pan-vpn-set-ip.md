#### Parser Content
```Java
{
Name = cef-pan-vpn-set-ip
  Vendor = Palo Alto Networks
  Product = GlobalProtect
  Lms = ArcSight
  DataType = "vpn-set-ip"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|Palo Alto Networks|""", """|globalprotect""", """"GlobalProtect gateway client configuration generated""" ]
  Fields = [
    """\Wrt=({time}\d{1,100})""",
    """exabeam_host=([^=]+@\s{0,100})?({host}[^\s]+)""",
    """\Wdvchost=({host}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """Private IP:\s?({src_translated_ip}[a-fA-F\d.:]+)""",
    """User name:\s{1,100}({user}[\w.'\-\\$]+?)\.?(\s|,|"|$)""",
    """User name:\s{1,100}({user_email}[^@\s]+@[^\s,]+),""",
    """Client OS( version)?:\s{1,100}({os}[^":]+)(,|\.)"""
  ]
}
```