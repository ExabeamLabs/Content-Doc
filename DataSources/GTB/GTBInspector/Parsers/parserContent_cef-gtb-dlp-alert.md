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
    """\Wdst=({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """\Wcs2=({protocol}[^=]{1,2000}?)\s{1,100}\w+=""",
    """\Wshost=(|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wspt=({src_port}\d{1,100})""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]{1,2000})""",
    """\Wdvc=(|({host}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wsuser=({user_email}[^=\s]{1,2000})""",
    """\Wsuser=[^=]{0,2000}?<({user_email}[^<]{1,2000})>""",
    """\Wcs5=(|({subject}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """CEF[^\|]{1,2000}?\|GTB\|GTBInspector\|[^\|]{1,2000}?\|({alert_type}[^\|]{1,2000}?)\|({alert_name}[^\|]{1,2000})\|({alert_severity}\d{1,100})"""
    """\sduser=([\s"]{1,2000}suser=|[\s"]{0,2000}({target}.*?)[\s"]{0,2000}suser=)"""
  ]
}
```