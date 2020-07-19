#### Parser Content
```Java
{
Name = s-trendmicro-security-alert-3
  Vendor = Trend Micro
  Product = OfficeScan
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "M/dd/yyyy HH:mm:ss"
  Conditions = [ """TMCM:EVT_URL_CONTENT_FILTERING""" ]
  Fields = [
    """\sEvent time \(local\)="({time}\d+\/\d+\/\d\d\d\d \d\d:\d\d:\d\d)""",
    """({host}[\w.\-]+)\s+TMCM:({alert_type}\w+)""",
    """\sURL="({malware_url}[^"]+)""",
    """\sDestination IP="({src_ip}[^"]+)""",
    """\sDomain="({domain}[^"]+)""",
    """\sClient host name="({src_host}[^"]+)""",
    """\sURL="(\w+:\/\/)?[^\/"]*?({top_domain}[^\s.]+(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+)(\/|")""",
  ]
  DupFields = [ "top_domain->alert_name" ]
}

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