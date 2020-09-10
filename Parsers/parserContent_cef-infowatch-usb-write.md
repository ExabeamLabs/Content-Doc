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
    """\Wrt=({time}\d+)""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]+)""",
    """\Wshost=({src_host}.+?)(\s+[\w\.]+=|\s*$)""",
    """\Wact=({outcome}.+?)(\s+[\w\.]+=|\s*$)""",
    """\Wsntdom=({user}[^@]+?)@({domain}[^@]+?)(\s+[\w\.]+=|\s*$)""",
    """\Wsuser=({user}.+?)(\s+[\w\.]+=|\s*$)""",
    """\Wfname=({file_name}.+?(?:\.({file_ext}[^\.]+?))?)(\s+[\w\.]+=|\s*$)""",
    """\WfilePath=({file_path}({file_parent}[^=]*?[\\\/]+)?[^\\\/]+?)(\s+[\w\.]+=|\s*$)""",
    """\Wdvc=({host}.+?)(\s+[\w\.]+=|\s*$)""",
    """\Wdvchost=({host}.+?)(\s+[\w\.]+=|\s*$)""",
    """\Wsuid=({user_fullname}.+?)(\s+[\w\.]+=|\s*$)""",
  ]
}
```