#### Parser Content
```Java
{
Name = cef-scbpam-app-activity
  Vendor = Dell
  Product = One Identity Manager
  Lms = ArcSight
  DataType = "app-activity"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|SCB|PAM|""" ]
  Fields = [
    """\|SCB\|PAM\|([^\|]*\|){2}({activity}[^\|]+)""",
    """\ssuser=({user}.+?)(\s+\w+=|\s*$)""",
    """\sdhost=({dest_host}.+?)(\s+\w+=|\s*$)""",
    """\sOtherInfo:\s*({object}[^\s]+?)(\s+\w+=|\s*$)""",
    """\sduser=({object}.+?)(\s+\w+=|\s*$)""",
    """\sdvc=({host}.+?)(\s+\w+=|\s*$)""",
    """\sdvchost=({host}.+?)(\s+\w+=|\s*$)""",
    """\srt=({time}\d+)""",
    """\sOtherInfo:\s*({additional_info}.+?)(\s+\w+=|\s*$)""",
    """({app}PAM)""",
  ]
}
```