#### Parser Content
```Java
{
Name = cef-checkpoint-vpn-login-1
  Vendor = Check Point Software
  Product = Check Point Security Gateway
  Lms = ArcSight
  DataType = "vpn-start"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|Check Point|""", """act=IP Changed""", """product=Identity Awareness""" ]
  Fields = [
    """\Wrt=({time}\d{1,100})""",
    """\Wdvc=({host}[A-Fa-f:\d.]+)""",
    """\Wduser=({user_lastname}[^\,=]+),\s{0,100}({user_firstname}[^\(=]+?)\s{0,100}(\(({user}[^\s\)=]+)\))?\s{1,100}(\w+=|$)""",
    """\Wsntdom=({domain}[^\s]+)""",
    """\Worigin=({src_ip}[A-Fa-f:\d.]+)""",
    """\Wsrc=({src_translated_ip}[A-Fa-f:\d.]+)""",
  ]
}
```