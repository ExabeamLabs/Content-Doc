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
    """\|SCB\|PAM\|([^\|]{0,2000}\|){2}({activity}[^\|]{1,2000})""",
    """\ssuser=({user}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\sdhost=({dest_host}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\sOtherInfo:\s{0,100}({object}[^\s]{1,2000}?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\sduser=({object}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\sdvc=({host}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\sdvchost=({host}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\srt=({time}\d{1,100})""",
    """\sOtherInfo:\s{0,100}({additional_info}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """({app}PAM)""",
  ]
}
```