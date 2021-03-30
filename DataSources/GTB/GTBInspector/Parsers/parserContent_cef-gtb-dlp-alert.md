#### Parser Content
```Java
{
Name = cef-gtb-dlp-alert
  Vendor = GTB
  Product = GTBInspector
  Lms = ArcSight
  DataType = "dlp-alert"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|GTB|GTBInspector|""", """externalId=""" ]
  Fields = [
    """\Wrt=({time}\d+)""",
    """\Wdhost=(|({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}.+?))(\s+\w+=|\s*$)""",
    """\Wdpt=({dest_port}\d+)""",
    """\Wdst=({dest_ip}[a-fA-F\d.:]+)""",
    """\Wcs2=({protocol}[^=]+?)\s+\w+=""",
    """\Wshost=(|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}.+?))(\s+\w+=|\s*$)""",
    """\Wspt=({src_port}\d+)""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]+)""",
    """\Wdvc=(|({host}.+?))(\s+\w+=|\s*$)""",
    """\Wsuser=({user_email}[^=\s]+)""",
    """\Wsuser=[^=]*?<({user_email}[^<]+)>""",
    """\Wcs5=(|({subject}.+?))(\s+\w+=|\s*$)""",
    """CEF[^\|]+?\|GTB\|GTBInspector\|[^\|]+?\|({alert_type}[^\|]+?)\|({alert_name}[^\|]+)\|({alert_severity}\d+)"""
    """\sduser=([\s"]+suser=|[\s"]*({target}.*?)[\s"]*suser=)"""
  ]
}
```