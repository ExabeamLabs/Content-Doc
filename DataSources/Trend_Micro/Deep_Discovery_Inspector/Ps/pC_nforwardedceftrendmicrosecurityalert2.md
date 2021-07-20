#### Parser Content
```Java
{
Name = n-forwarded-cef-trendmicro-security-alert-2
  Vendor = Trend Micro
  Product = Deep Discovery Inspector
  Lms = ArcSight
  DataType = "alert"
  TimeFormat = "epoch"
  Conditions = [ "|McAfee|ESM", "|473-" ]
  Fields = [
    """CEF:([^\|]{0,2000}\|){5}({alert_name}[^\|]{1,2000})\|({alert_severity}[^\|]{1,2000})""",
    """\WeventId=({alert_id}\d{1,100})""",
    """\WnitroDestination_Hostname=({host}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wrt=({time}\d{1,100})""",
    """\Wdst=({src_ip}[a-fA-F\d.:]{1,2000})""",
    """\Wdpt=({src_port}\d{1,100})""",
    """\Wsrc=({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """\Wspt=({dest_port}\d{1,100})""",
    """\Wshost=({dest_host}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wact=({action}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wcat=({alert_type}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
  ]
}
```