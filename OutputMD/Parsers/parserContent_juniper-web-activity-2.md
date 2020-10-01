#### Parser Content
```Java
{
Name = juniper-web-activity-2
  Vendor = Juniper Networks
  Product = Juniper VPN
  Lms = Direct
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ PulseSecure:""", """ Host: """, """, Request: """ ]
  Fields = [
    """({time}\d+-\d+-\d+T\d+:\d+:\d+Z)\s+({host}[\w\-.]+)\s+PulseSecure:""",
    """PulseSecure:.+?({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)\s+\-\s+({host}[\w\-.]+)""",
    """PulseSecure:.*?\[({src_ip}[A-Fa-f:\d.]+)\]\s*\d+\(({realm}[^\)]+)\)\s*\[({role}[^\]]+)\]""",
    """PulseSecure:.*?\[({src_ip}[a-fA-F:\d.]+)\]\s+(({domain}[^\\]+)\\)?(?:({user_email}[^@\s]+@[^@\s]+)|({user}[^\s]+))\(({realm}[^\)]+)?""",
    """\WRequest:\s*({method}[^\s"]+)\s+({uri_path}\/[^",\s]*)""",
    """\WHost:\s*({web_domain}[^\s",:]+)""",
    """\WHost:\s*[^\s",:]*?({top_domain}(?!(?:\d+\.){3}\d+)[^\.\s\/:]+(?=(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|tr))+(\s|\/|:|,|$))[^\s\/:",]+)""",
    """\w+\s+\d+\s+\d+:\d+:\d+\s+({firewall}[A-Fa-f:\d.]+)\s""",
  ]
}
```