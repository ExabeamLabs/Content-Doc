#### Parser Content
```Java
{
Name = cef-trendmicro-security-alert-1
  Vendor = Trend Micro
  Product = Deep Discovery Inspector
  Lms = ArcSight
  DataType = "alert"
  TimeFormat = "MMM dd yyyy HH:mm:ss zZ"
  Conditions = [ """CEF:""", """|Trend Micro|Deep Discovery Inspector|""", """dvc=""" ]
  Fields = [
    """CEF:([^\|]{0,2000}\|){5}({alert_name}[^\|]{1,2000})\|({alert_severity}[^\|]{1,2000})""",
    """\WeventId=({alert_id}\d{1,100})""",
    """\Wdvc=({host}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wdvchost=({host}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wrt=({time}\w+\s{1,100}\d\d \d\d\d\d \d\d:\d\d:\d\d \S+)""",
    """\Wshost=({src_host}[^\s]{1,2000})""",
    """\Wdhost=({dest_host}[^\s]{1,2000})""",
    """\Wapp=({app}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wdst=({src_ip}[a-fA-F\d.:]{1,2000})""",
    """\Wdpt=({src_port}\d{1,100})""",
    """\Wsrc=({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """\Wspt=({dest_port}\d{1,100})""",
    """\Wact=({action}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wcn3=({threat_type}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wcat=({alert_type}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """CEF:(?:[^\|]{0,2000}\|){5}({alert_name}[^\|]{1,2000})\|(Unknown|({alert_severity}[^\|]{1,2000}))\|\w+="""
  ]
}
```