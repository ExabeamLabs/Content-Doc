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
    """CEF:([^\|]*\|){5}({device_type}[^\|]+)""",
    """\Wrt=({time}\d{1,100})""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]+)""",
    """\Wshost=({src_host}.+?)(\s{1,100}[\w\.]+=|\s{0,100}$)""",
    """\Wact=({outcome}.+?)(\s{1,100}[\w\.]+=|\s{0,100}$)""",
    """\Wsntdom=({user}[^@]+?)@({domain}[^@]+?)(\s{1,100}[\w\.]+=|\s{0,100}$)""",
    """\Wsuser=({user}.+?)(\s{1,100}[\w\.]+=|\s{0,100}$)""",
    """\Wfname=({file_name}.+?(?:\.({file_ext}[^\.]+?))?)(\s{1,100}[\w\.]+=|\s{0,100}$)""",
    """\WfilePath=({file_path}({file_parent}[^=]*?[\\\/]+)?[^\\\/]+?)(\s{1,100}[\w\.]+=|\s{0,100}$)""",
    """\Wdvc=({host}.+?)(\s{1,100}[\w\.]+=|\s{0,100}$)""",
    """\Wdvchost=({host}.+?)(\s{1,100}[\w\.]+=|\s{0,100}$)""",
    """\Wsuid=({user_fullname}.+?)(\s{1,100}[\w\.]+=|\s{0,100}$)""",
  ]
}
```