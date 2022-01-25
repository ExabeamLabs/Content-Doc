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
    """\Wdvc=({host}[A-Fa-f:\d.]{1,2000})""",
    """\Wduser=({user_lastname}[^\,=]{1,2000}),\s{0,100}({user_firstname}[^\(=]{1,2000}?)\s{0,100}(\(({user}[^\s\)=]{1,2000})\))?\s{1,100}(\w+=|$)""",
    """\Wsntdom=({domain}[^\s]{1,2000})""",
    """\Worigin=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Wsrc=({src_translated_ip}[A-Fa-f:\d.]{1,2000})""",
  ]


}
```