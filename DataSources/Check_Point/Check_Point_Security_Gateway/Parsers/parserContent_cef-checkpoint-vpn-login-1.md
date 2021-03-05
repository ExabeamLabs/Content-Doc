#### Parser Content
```Java
{
Name = cef-checkpoint-vpn-login-1
  Vendor = Check Point
  Product = Check Point Security Gateway
  Lms = ArcSight
  DataType = "vpn-start"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|Check Point|""", """act=IP Changed""", """product=Identity Awareness""" ]
  Fields = [
    """\Wrt=({time}\d+)""",
    """\Wdvc=({host}[A-Fa-f:\d.]+)""",
    """\Wduser=({user_lastname}[^\,=]+),\s*({user_firstname}[^\(=]+?)\s*(\(({user}[^\s\)=]+)\))?\s+(\w+=|$)""",
    """\Wsntdom=({domain}[^\s]+)""",
    """\Worigin=({src_ip}[A-Fa-f:\d.]+)""",
    """\Wsrc=({src_translated_ip}[A-Fa-f:\d.]+)""",
  ]
}
```