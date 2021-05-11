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
    """\Wrt=({time}\d{1,100})""",
    """\Wdhost=(|({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wdpt=({dest_port}\d{1,100})""",
    """\Wdst=({dest_ip}[a-fA-F\d.:]+)""",
    """\Wcs2=({protocol}[^=]+?)\s{1,100}\w+=""",
    """\Wshost=(|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wspt=({src_port}\d{1,100})""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]+)""",
    """\Wdvc=(|({host}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wsuser=({user_email}[^=\s]+)""",
    """\Wsuser=[^=]*?<({user_email}[^<]+)>""",
    """\Wcs5=(|({subject}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """CEF[^\|]+?\|GTB\|GTBInspector\|[^\|]+?\|({alert_type}[^\|]+?)\|({alert_name}[^\|]+)\|({alert_severity}\d{1,100})"""
    """\sduser=([\s"]+suser=|[\s"]*({target}.*?)[\s"]*suser=)"""
  ]
}
```