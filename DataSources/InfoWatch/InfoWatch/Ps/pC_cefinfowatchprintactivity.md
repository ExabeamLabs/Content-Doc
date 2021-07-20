#### Parser Content
```Java
{
Name = cef-infowatch-print-activity
  Vendor = InfoWatch
  Product = InfoWatch
  Lms = ArcSight
  DataType = "print-activity"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|Print|""", """|DLP|DLP TM""" ]
  Fields = [
    """({activity}Print)""",
    """\Wact=({outcome}.+?)(\s{1,100}[\w\.]{1,2000}=|\s{0,100}$)""",
    """\Wrt=({time}\d{1,100})""",
    """\Wshost=({src_host}.+?)(\s{1,100}[\w\.]{1,2000}=|\s{0,100}$)""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]{1,2000})""",
    """\Wsntdom=({user}[^@=]{1,2000})@({domain}[^@]{1,2000}?)(\s{1,100}[\w\.]{1,2000}=|\s{0,100}$)""",
    """\Wsuser=({user}.+?)(\s{1,100}[\w\.]{1,2000}=|\s{0,100}$)""",
    """\Wsuid=({user_fullname}.+?)(\s{1,100}[\w\.]{1,2000}=|\s{0,100}$)""",
    """\Wfname=({object}.+?)(\s{1,100}[\w\.]{1,2000}=|\s{0,100}$)""",
    """\Wdvchost=({host}.+?)(\s{1,100}[\w\.]{1,2000}=|\s{0,100}$)""",
    """\Wcs3=({additional_info}.+?)(\s{1,100}[\w\.]{1,2000}=|\s{0,100}$)""",
    """\Wad\.categories=({categories}.+?)(\s{1,100}[\w\.]{1,2000}=|\s{0,100}$)""",
    """\Wad\.fingerprints=({fingerprints}.+?)(\s{1,100}[\w\.]{1,2000}=|\s{0,100}$)""",
    """\Wad\.device__name=({printer_name}.*?({dest_host}[^\\\/]{1,2000}?))(\s{1,100}[\w\.]{1,2000}=|\s{0,100}$)""",
  ]
  DupFields = [ object->file_name ]
}
```