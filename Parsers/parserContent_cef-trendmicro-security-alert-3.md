#### Parser Content
```Java
{
Name = cef-trendmicro-security-alert-3
  Vendor = Trend Micro
  Product = Deep Security Agent
  Lms = ArcSight
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSSZ"
  Conditions = [ """CEF:""", """|Trend Micro|Deep Security Agent|""", """TrendMicroDsMalwareTargetType=""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d+(\+|\-)\d+)""",
    """({host}[\w.\-]+)\s+CEF:([^\|]*\|){5}({alert_name}[^\|]+)\|({alert_severity}[^\|]+)""",
    """\Wdvchost=({src_host}.+?)(\s+\w+=|\s*$)""",
    """\Wcs3=({malware_url}.+?)(\s+\w+=|\s*$)""",
    """\Wact=({outcome}.+?)(\s+\w+=|\s*$)""",
    """({alert_type}Malware)""",
  ]
}
```