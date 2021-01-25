#### Parser Content
```Java
{
Name = juniper-web-activity-2
  Vendor = Juniper VPN
  Product = Juniper VPN
  Lms = Direct
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """ PulseSecure:""", """ Host: """, """, Request: """ ]
  Fields = [
	  """({time}\d+-\d+-\d+T\d+:\d+:\d+Z)\s+({host}[\w\-.]+)\s+PulseSecure:""",
    """PulseSecure:.*?\[({src_ip}[A-Fa-f:\d.]+)\]\s*\d+\(({realm}[^\)]+)\)\s*\[({role}[^\]]+)\]""",
    """\WRequest:\s*({method}[^\s"]+)\s+({uri_path}\/[^",\s]*)""",
    """\WHost:\s*({web_domain}[^\s",:]+)""",
    """\WHost:\s*[^\s",:]*?({top_domain}(?!(?:\d+\.){3}\d+)[^\.\s\/:]+(?=(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|tr))+(\s|\/|:|,|$))[^\s\/:",]+)""",
    """\w+\s+\d+\s+\d+:\d+:\d+\s+({firewall}[A-Fa-f:\d.]+)\s""",
  ]
}
```