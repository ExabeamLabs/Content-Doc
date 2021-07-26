#### Parser Content
```Java
{
Name = cef-infowatch-usb-write
  Vendor = InfoWatch
  Product = InfoWatch
  Lms = ArcSight
  DataType = "usb-activity"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|DLP TM""", """|External device|""" ]
  Fields = [
    """CEF:([^\|]{0,2000}\|){5}({device_type}[^\|]{1,2000})""",
    """\Wrt=({time}\d{1,100})""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]{1,2000})""",
    """\Wshost=({src_host}.+?)(\s{1,100}[\w\.]{1,2000}=|\s{0,100}$)""",
    """\Wact=({outcome}.+?)(\s{1,100}[\w\.]{1,2000}=|\s{0,100}$)""",
    """\Wsntdom=({user}[^@]{1,2000}?)@({domain}[^@]{1,2000}?)(\s{1,100}[\w\.]{1,2000}=|\s{0,100}$)""",
    """\Wsuser=({user}.+?)(\s{1,100}[\w\.]{1,2000}=|\s{0,100}$)""",
    """\Wfname=({file_name}.+?(?:\.({file_ext}[^\.]{1,2000}?))?)(\s{1,100}[\w\.]{1,2000}=|\s{0,100}$)""",
    """\WfilePath=({file_path}({file_parent}[^=]{0,2000}?[\\\/]{1,2000})?[^\\\/]{1,2000}?)(\s{1,100}[\w\.]{1,2000}=|\s{0,100}$)""",
    """\Wdvc=({host}.+?)(\s{1,100}[\w\.]{1,2000}=|\s{0,100}$)""",
    """\Wdvchost=({host}.+?)(\s{1,100}[\w\.]{1,2000}=|\s{0,100}$)""",
    """\Wsuid=({user_fullname}.+?)(\s{1,100}[\w\.]{1,2000}=|\s{0,100}$)""",
  ]
}
```