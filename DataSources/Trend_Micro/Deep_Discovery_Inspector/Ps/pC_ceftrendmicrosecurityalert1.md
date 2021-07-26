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
    """\Wdvc=({host}[^=]{1,2000}?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wdvchost=({host}[^=]{1,2000}?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wrt=({time}\w+\s{1,100}\d\d \d\d\d\d \d\d:\d\d:\d\d \S+)""",
    """\Wshost=((\d{1,3}\.){3}\d{1,3}|({src_host}[^\s]{1,2000}))""",
    """\Wdhost=((\d{1,3}\.){3}\d{1,3}|({dest_host}[^\s]{1,2000}))""",
    """\Wapp=({app}[^=]{1,2000}?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wdst=({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """\Wdpt=({dest_port}\d{1,100})""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]{1,2000})""",
    """\Wspt=({src_port}\d{1,100})""",
    """\Wact=({action}[^=]{1,2000}?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wcn3=({threat_type}[^=]{1,2000}?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wcat=({alert_type}[^=]{1,2000}?)(\s{1,100}\w+=|\s{0,100}$)""",
    """CEF:(?:[^\|]{0,2000}\|){5}({alert_name}[^\|]{1,2000})\|(Unknown|({alert_severity}[^\|]{1,2000}))\|\w+="""
  ]
}
```