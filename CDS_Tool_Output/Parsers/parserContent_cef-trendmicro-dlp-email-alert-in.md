#### Parser Content
```Java
{
Name = cef-trendmicro-dlp-email-alert-in
  Vendor = Trend Micro
  Product = Deep Discovery Email Inspector
  Lms = ArcSight
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """CEF:""", """|Trend Micro|""", """|TMES|""" , """|DETECTION|"""]
  Fields = [
    """\Wrt=({time}\d+-\d+-\d+\s+\d\d:\d\d:\d\d)""",
    """\w+\s+\d+\s+\d+:\d+:\d+\s+({host}[\w\-.]+)\s""",
    """\Wcs1=({alert_type}.+?)\s+(\w+=|$)""",
    """\Wcs2=({domain}.+?)\s+(\w+=|$)""",
    """\Wsuser=({sender}[^\s@]+@({external_domain}[^\s@]+))""",
    """\Wduser=({recipients}({recipient}[^\s@;,]+@[^\s@;,]+).*?)\s+(\w+=|$)""",
    """\Wcs3=({direction}.+?)\s+(\w+=|$)""",
    """\Wmsg=\s*({subject}.+?)\s+(\w+=|$)""",
    """\Wcn1=({bytes}.+?)\s+(\w+=|$)""",
    """\Wact=({outcome}.+?)\s+(\w+=|$)""",
    """\Wcs5=({alert_name}.+?)\s+(\w+=|$)""",
  ]
  DupFields = [ "sender->external_address" ]
}
```