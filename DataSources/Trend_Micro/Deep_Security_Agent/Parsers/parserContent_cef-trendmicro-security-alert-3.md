#### Parser Content
```Java
{
Name = cef-trendmicro-security-alert-3
  Vendor = Trend Micro
  Product = Deep Security Agent
  Lms = ArcSight
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """CEF:""", """|Trend Micro|Deep Security Agent|""", """TrendMicroDsMalwareTargetType=""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """({host}[\w.\-]{1,2000})\s{1,100}CEF:([^\|]{0,2000}\|){5}({alert_name}[^\|]{1,2000})\|({alert_severity}[^\|]{1,2000})""",
    """CEF:([^\|]{0,2000}\|){4}({alert_id}\d{1,100})"""
    """\Wdvchost=({src_host}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wcs3=({malware_url}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wact=({outcome}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """({alert_type}Malware)""",
  ]
}
```