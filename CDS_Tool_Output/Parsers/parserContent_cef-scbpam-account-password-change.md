#### Parser Content
```Java
{
Name = cef-scbpam-account-password-change
  Vendor = Dell
  Product = Dell Quest TPAM
  Lms = ArcSight
  DataType = "password-change"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|SCB|PAM|""", """|Force Change|""" ]
  Fields = [
    """\ssuser=({user}.+?)(\s+\w+=|\s*$)""",
    """\sdhost=({dest_host}.+?)(\s+\w+=|\s*$)""",
    """\sduser=({target_user}.+?)(\s+\w+=|\s*$)""",
    """\sdvc=({host}.+?)(\s+\w+=|\s*$)""",
    """\sdvchost=({host}.+?)(\s+\w+=|\s*$)""",
    """\srt=({time}\d+)""",
    """\sOtherInfo:\s*({outcome}.+?)(\s+\w+=|\s*$)"""
  ]
}
```