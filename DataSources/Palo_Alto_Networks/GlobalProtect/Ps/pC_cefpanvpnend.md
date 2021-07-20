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
    """\Wrt=({time}\d{1,100})""",
    """User name:\s{0,100}({user}[\w.'\-\\$]{1,2000}?)\.?(\s|,|"|$)""",
    """User name:\s{0,100}({user_email}[^@\s]{1,2000}@[^\s,]{1,2000}),""",
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[^\s]{1,2000})""",
    """\Wdvchost=({host}.+?)(\s{1,100}\w+=|\s{0,100}$)"""
  ]
}
```