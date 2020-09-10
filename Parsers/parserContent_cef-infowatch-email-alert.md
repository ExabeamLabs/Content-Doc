#### Parser Content
```Java
{
Name = cef-infowatch-email-alert
  Vendor = InfoWatch
  Lms = ArcSight
  DataType = "dlp-email-alert"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|Mail on Client|""", """|DLP|DLP TM""" ]
  Fields = [
    """\Wact=({outcome}.+?)(\s+[\w\.]+=|\s*$)""",
    """\Wrt=({time}\d+)""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]+)""",
    """\Wsntdom=({sender}[^@=]+?@({external_domain_sender}[^@]+?))(\s+[\w\.]+=|\s*$)""",
    """\Wsuser=({user}.+?)(\s+[\w\.]+=|\s*$)""",
    """\Wduser=({recipients}({recipient}[^;@=]+@({external_domain_recipient}[^;\s]+)).*?)(\s+[\w\.]+=|\s*$)""",
    """\Wdvchost=({host}.+?)(\s+[\w\.]+=|\s*$)""",
    """\Wdvc=({host}.+?)(\s+[\w\.]+=|\s*$)""",   
  ]
}
```