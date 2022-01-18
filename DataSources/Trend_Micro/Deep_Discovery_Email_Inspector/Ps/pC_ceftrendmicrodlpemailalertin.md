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
    """\Wrt=({time}\d{1,100}-\d{1,100}-\d{1,100}\s{1,100}\d\d:\d\d:\d\d)""",
    """\w+\s{1,100}\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}({host}[\w\-.]{1,2000})\s""",
    """\Wcs1=({alert_type}.+?)\s{1,100}(\w+=|$)""",
    """\Wcs2=({domain}.+?)\s{1,100}(\w+=|$)""",
    """\Wsuser=({sender}[^\s@]{1,2000}@({external_domain}[^\s@]{1,2000}))""",
    """\Wduser=({recipients}({recipient}[^\s@;,]{1,2000}@[^\s@;,]{1,2000}).*?)\s{1,100}(\w+=|$)""",
    """\Wcs3=({direction}.+?)\s{1,100}(\w+=|$)""",
    """\Wmsg=\s{0,100}({subject}.+?)\s{1,100}(\w+=|$)""",
    """\Wcn1=({bytes}.+?)\s{1,100}(\w+=|$)""",
    """\Wact=({outcome}.+?)\s{1,100}(\w+=|$)""",
    """\Wcs5=({alert_name}.+?)\s{1,100}(\w+=|$)""",
  ]
  DupFields = [ "sender->external_address" ]


}
```