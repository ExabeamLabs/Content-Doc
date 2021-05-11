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
    """CEF:([^\|]*\|){5}({alert_name}[^\|]+)\|({alert_severity}[^\|]+)""",
    """\WeventId=({alert_id}\d{1,100})""",
    """\Wdvc=({host}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wdvchost=({host}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wrt=({time}\w+\s{1,100}\d\d \d\d\d\d \d\d:\d\d:\d\d \S+)""",
    """\Wshost=({src_host}[^\s]+)""",
    """\Wdhost=({dest_host}[^\s]+)""",
    """\Wapp=({app}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wdst=({src_ip}[a-fA-F\d.:]+)""",
    """\Wdpt=({src_port}\d{1,100})""",
    """\Wsrc=({dest_ip}[a-fA-F\d.:]+)""",
    """\Wspt=({dest_port}\d{1,100})""",
    """\Wact=({action}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wcn3=({threat_type}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wcat=({alert_type}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """CEF:(?:[^\|]*\|){5}({alert_name}[^\|]+)\|(Unknown|({alert_severity}[^\|]+))\|\w+="""
  ]
}
```