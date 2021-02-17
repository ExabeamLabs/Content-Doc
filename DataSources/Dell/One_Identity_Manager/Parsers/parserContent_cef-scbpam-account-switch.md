#### Parser Content
```Java
{
Name = cef-scbpam-account-switch
  Vendor = Dell
  Product = One Identity Manager
  Lms = ArcSight
  DataType = "account-switch"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|SCB|PAM|""", """|Retrieve Password|""" ]
  Fields = [
    """\ssuser=({user}.+?)(\s+\w+=|\s*$)""",
    """\sdhost=({dest_host}.+?)(\s+\w+=|\s*$)""",
    """\sduser=({account}.+?)(\s+\w+=|\s*$)""",
    """\sdvc=({host}.+?)(\s+\w+=|\s*$)""",
    """\sdvchost=({host}.+?)(\s+\w+=|\s*$)""",
    """\srt=({time}\d+)""",
  ]
}
```