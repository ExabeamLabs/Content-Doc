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
    """\Wrt=({time}\d+)""",
    """exabeam_host=([^=]+@\s*)?({host}[^\s]+)""",
    """\Wdvchost=({host}.+?)(\s+\w+=|\s*$)""",
    """Private IP:\s?({src_translated_ip}[a-fA-F\d.:]+)""",
    """User name:\s+({user}[\w.'\-\\$]+?)\.?(\s|,|"|$)""",
    """User name:\s+({user_email}[^@\s]+@[^\s,]+),""",
    """Client OS( version)?:\s+({os}[^":]+)(,|\.)"""
  ]
}
```