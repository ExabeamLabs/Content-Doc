#### Parser Content
```Java
{
Name = cef-scbpam-account-password-change
  Vendor = Dell
  Product = One Identity Manager
  Lms = ArcSight
  DataType = "password-change"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|SCB|PAM|""", """|Force Change|""" ]
  Fields = [
    """\ssuser=({user}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\sdhost=({dest_host}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\sduser=({target_user}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\sdvc=({host}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\sdvchost=({host}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\srt=({time}\d{1,100})""",
    """\sOtherInfo:\s{0,100}({outcome}.+?)(\s{1,100}\w+=|\s{0,100}$)"""
  ]
}
```