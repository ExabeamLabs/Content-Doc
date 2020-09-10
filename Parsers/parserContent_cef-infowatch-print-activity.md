#### Parser Content
```Java
{
Name = cef-infowatch-print-activity
  Vendor = InfoWatch
  Lms = ArcSight
  DataType = "print-activity"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|Print|""", """|DLP|DLP TM""" ]
  Fields = [
    """({activity}Print)""",
    """\Wact=({outcome}.+?)(\s+[\w\.]+=|\s*$)""",
    """\Wrt=({time}\d+)""",
    """\Wshost=({src_host}.+?)(\s+[\w\.]+=|\s*$)""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]+)""",
    """\Wsntdom=({user}[^@=]+)@({domain}[^@]+?)(\s+[\w\.]+=|\s*$)""",
    """\Wsuser=({user}.+?)(\s+[\w\.]+=|\s*$)""",
    """\Wsuid=({user_fullname}.+?)(\s+[\w\.]+=|\s*$)""",
    """\Wfname=({object}.+?)(\s+[\w\.]+=|\s*$)""",
    """\Wdvchost=({host}.+?)(\s+[\w\.]+=|\s*$)""",
    """\Wcs3=({additional_info}.+?)(\s+[\w\.]+=|\s*$)""",
    """\Wad\.categories=({categories}.+?)(\s+[\w\.]+=|\s*$)""",
    """\Wad\.fingerprints=({fingerprints}.+?)(\s+[\w\.]+=|\s*$)""",
    """\Wad\.device__name=({printer_name}.*?({dest_host}[^\\\/]+?))(\s+[\w\.]+=|\s*$)""",
  ]
  DupFields = [ object->file_name ]
}
```