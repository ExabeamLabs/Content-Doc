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
    """\WeventId=({alert_id}\d+)""",
    """\Wdvc=({host}.+?)(\s+\w+=|\s*$)""",
    """\Wdvchost=({host}.+?)(\s+\w+=|\s*$)""",
    """\Wrt=({time}\w+\s+\d\d \d\d\d\d \d\d:\d\d:\d\d \S+)""",
    """\Wshost=({src_host}[^\s]+)""",
    """\Wdhost=({dest_host}[^\s]+)""",
    """\Wapp=({app}.+?)(\s+\w+=|\s*$)""",
    """\Wdst=({src_ip}[a-fA-F\d.:]+)""",
    """\Wdpt=({src_port}\d+)""",
    """\Wsrc=({dest_ip}[a-fA-F\d.:]+)""",
    """\Wspt=({dest_port}\d+)""",
    """\Wact=({action}.+?)(\s+\w+=|\s*$)""",
    """\Wcn3=({threat_type}.+?)(\s+\w+=|\s*$)""",
    """\Wcat=({alert_type}.+?)(\s+\w+=|\s*$)""",
    """CEF:(?:[^\|]*\|){5}({alert_name}[^\|]+)\|(Unknown|({alert_severity}[^\|]+))\|\w+="""
  ]
}
```