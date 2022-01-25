#### Parser Content
```Java
{
Name = cef-infowatch-email-alert
  Vendor = InfoWatch
  Product = InfoWatch
  Lms = ArcSight
  DataType = "dlp-email-alert"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|Mail on Client|""", """|DLP|DLP TM""" ]
  Fields = [
    """\Wact=({outcome}.+?)(\s{1,100}[\w\.]{1,2000}=|\s{0,100}$)""",
    """\Wrt=({time}\d{1,100})""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]{1,2000})""",
    """\Wsntdom=({sender}[^@=]{1,2000}?@[^@]{1,2000}?)(\s{1,100}[\w\.]{1,2000}=|\s{0,100}$)""",
    """\Wsuser=({user}.+?)(\s{1,100}[\w\.]{1,2000}=|\s{0,100}$)""",
    """\Wduser=({recipients}({recipient}[^;@=]{1,2000}@[^;\s]{1,2000}).*?)(\s{1,100}[\w\.]{1,2000}=|\s{0,100}$)""",
    """\Wdvchost=({host}.+?)(\s{1,100}[\w\.]{1,2000}=|\s{0,100}$)""",
    """\Wdvc=({host}.+?)(\s{1,100}[\w\.]{1,2000}=|\s{0,100}$)""",   
  ]


}
```