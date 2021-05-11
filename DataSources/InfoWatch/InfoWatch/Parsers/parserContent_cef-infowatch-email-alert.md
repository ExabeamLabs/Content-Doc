#### Parser Content
```Java
{
Name = cef-infowatch-email-alert
  Vendor = InfoWatch
  Product = InfoWatch
  Lms = ArcSight
  DataType = "dlp-email-alert"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|Mail on Client|""", """|DLP|DLP TM""" ]
  Fields = [
    """\Wact=({outcome}.+?)(\s{1,100}[\w\.]+=|\s{0,100}$)""",
    """\Wrt=({time}\d{1,100})""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]+)""",
    """\Wsntdom=({sender}[^@=]+?@({external_domain_sender}[^@]+?))(\s{1,100}[\w\.]+=|\s{0,100}$)""",
    """\Wsuser=({user}.+?)(\s{1,100}[\w\.]+=|\s{0,100}$)""",
    """\Wduser=({recipients}({recipient}[^;@=]+@({external_domain_recipient}[^;\s]+)).*?)(\s{1,100}[\w\.]+=|\s{0,100}$)""",
    """\Wdvchost=({host}.+?)(\s{1,100}[\w\.]+=|\s{0,100}$)""",
    """\Wdvc=({host}.+?)(\s{1,100}[\w\.]+=|\s{0,100}$)""",   
  ]
}
```