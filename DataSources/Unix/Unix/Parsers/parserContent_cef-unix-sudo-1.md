#### Parser Content
```Java
{
Name = cef-unix-sudo-1
    Vendor = Unix
  Product = Unix
    Lms = ArcSight
    DataType = "unix-account-switch"
    TimeFormat = "epoch"
    Conditions = [ """CEF:""", """|Unix|Unix|""", """; COMMAND""", """ deviceProcessName=sudo """ ]
    Fields = [
      """\srt=({time}\d{1,100})""",
      """\sdvc=({host}\S+)(\s{1,100}\w+=|\s{0,100}$)""",
      """\sdvchost=({host}\S+)(\s{1,100}\w+=|\s{0,100}$)""",
      """\sdhost=({dest_host}\S+)(\s{1,100}\w+=|\s{0,100}$)""",
      """\sdst=({dest_ip}\S+)(\s{1,100}\w+=|\s{0,100}$)""",
      """\ssuser=({user}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
      """\ssuid=({user_uid}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
      """\sduser=({account}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
      """({event_code}sudo)"""
    ]
    DupFields = [ "event_code->process_name" ]
  }
```