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
    """\ssuser=({user}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\sdhost=({dest_host}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\sduser=({account}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\sdvc=({host}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\sdvchost=({host}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\srt=({time}\d{1,100})""",
  ]
}
```