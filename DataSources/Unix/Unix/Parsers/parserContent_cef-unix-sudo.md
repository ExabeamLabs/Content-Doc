#### Parser Content
```Java
{
Name = cef-unix-sudo
    Vendor = Unix
    Product = Unix
    Lms = ArcSight
    DataType = "unix-account-switch"
    TimeFormat = "epoch"
    Conditions = [ """CEF:""", """|Unix|Unix|""", """|User Executed Command|""", """ deviceProcessName=sudo """ ]
    Fields = [
      """\srt=({time}\d{1,100})""",
      """\sdvc=({host}\S+)(\s{1,100}\w+=|\s{0,100}$)""",
      """\sdvchost=({host}\S+)(\s{1,100}\w+=|\s{0,100}$)""",
      """\sdhost=({dest_host}\S+)(\s{1,100}\w+=|\s{0,100}$)""",
      """\sdst=({dest_ip}\S+)(\s{1,100}\w+=|\s{0,100}$)""",
      """\ssuser=(|({user}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
      """\ssuid=(|({user_uid}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
      """\sfname=((/usr)?/bin/)?su(\s{1,100}((-\w*[csgG]\s{1,100}("([^"\\]|\\\\|\\")+"|'.+?'|\S+))|-\w+|--(session-command|command|group|supp-group|shell)\s{1,100}("([^"\\]|\\\\|\\")+"|'.+?'|\S+)|--\w+|-))*\s{1,100}(?!-+)["']?({account}\S+)["']?(\s{1,100}\w+=|\s{0,100}$)""",
      """\sduser=(|({account}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
      """({event_code}sudo)"""
    ]
  }
```