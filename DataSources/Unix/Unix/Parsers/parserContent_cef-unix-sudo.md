#### Parser Content
```Java
{
Name = cef-unix-sudo
    Vendor = Unix
    Lms = ArcSight
    DataType = "unix-account-switch"
    TimeFormat = "epoch"
    Conditions = [ """CEF:""", """|Unix|Unix|""", """|User Executed Command|""", """ deviceProcessName=sudo """ ]
    Fields = [
      """\srt=({time}\d+)""",
      """\sdvc=({host}\S+)(\s+\w+=|\s*$)""",
      """\sdvchost=({host}\S+)(\s+\w+=|\s*$)""",
      """\sdhost=({dest_host}\S+)(\s+\w+=|\s*$)""",
      """\sdst=({dest_ip}\S+)(\s+\w+=|\s*$)""",
      """\ssuser=(|({user}.+?))(\s+\w+=|\s*$)""",
      """\ssuid=(|({user_uid}.+?))(\s+\w+=|\s*$)""",
      """\sduser=(|({account}.+?))(\s+\w+=|\s*$)""",
      """\sfname=((/usr)?/bin/)?su(\s+((-\w*[csgG]\s+("([^"\\]|\\\\|\\")+"|'.+?'|\S+))|-\w+|--(session-command|command|group|supp-group|shell)\s+("([^"\\]|\\\\|\\")+"|'.+?'|\S+)|--\w+|-))*\s+(?!-+)["']?({account}\S+)["']?(\s+\w+=|\s*$)""",
      """({event_code}sudo)"""
    ]
  }
```