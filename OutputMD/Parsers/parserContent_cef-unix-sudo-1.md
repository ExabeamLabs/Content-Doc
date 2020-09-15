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
      """\srt=({time}\d+)""",
      """\sdvc=({host}\S+)(\s+\w+=|\s*$)""",
      """\sdvchost=({host}\S+)(\s+\w+=|\s*$)""",
      """\sdhost=({dest_host}\S+)(\s+\w+=|\s*$)""",
      """\sdst=({dest_ip}\S+)(\s+\w+=|\s*$)""",
      """\ssuser=({user}.+?)(\s+\w+=|\s*$)""",
      """\ssuid=({user_uid}.+?)(\s+\w+=|\s*$)""",
      """\sduser=({account}.+?)(\s+\w+=|\s*$)""",
      """({event_code}sudo)"""
    ]
    DupFields = [ "event_code->process_name" ]
  }
```