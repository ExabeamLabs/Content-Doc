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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[^\s]{1,2000})""",
    """\Wdvchost=({host}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """Private IP:\s?({src_translated_ip}[a-fA-F\d.:]{1,2000})""",
    """User name:\s{1,100}({user}[\w.'\-\\$]{1,2000}?)\.?(\s|,|"|$)""",
    """User name:\s{1,100}({user_email}[^@\s]{1,2000}@[^\s,]{1,2000}),""",
    """Client OS( version)?:\s{1,100}({os}[^":]{1,2000})(,|\.)"""
  ]
}
```