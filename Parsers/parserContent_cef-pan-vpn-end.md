#### Parser Content
```Java
{
Name = cef-pan-vpn-end
  Vendor = Palo Alto Networks
  Product = GlobalProtect
  Lms = ArcSight
  DataType = "vpn-end"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|Palo Alto Networks|""", """|globalprotect""", """GlobalProtect gateway user logout succeeded""" ]
  Fields = [
    """\Wrt=({time}\d+)""",
    """User name:\s*({user}[\w.'\-\\$]+?)\.?(\s|,|"|$)""",
    """User name:\s*({user_email}[^@\s]+@[^\s,]+),""",
    """exabeam_host=([^=]+@\s*)?({host}[^\s]+)""",
    """\Wdvchost=({host}.+?)(\s+\w+=|\s*$)"""
  ]
}
```