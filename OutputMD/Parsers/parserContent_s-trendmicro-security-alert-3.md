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
    """\sDestination IP="({dest_ip}[^"]+)""",
    """\sDomain="({domain}[^"]+)""",
    """\sClient host name="({src_host}[^"]+)""",
    """\sURL="(\w+:\/\/)?[^\/"]*?({top_domain}[^\s.]+(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+)(\/|")""",
    """\sSource IP="({src_ip}[^"]+)""", 
  ]
  DupFields = [ "top_domain->alert_name" ]
}
```