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
    """({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}Z)\s{1,100}(::ffff:)?({host}[\w\-.]+)\s{1,100}PulseSecure:""",
    """PulseSecure:.+?({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)\s{1,100}\-\s{1,100}(::ffff:)?({host}[\w\-.]+)""",
    """PulseSecure:.*?\[(::ffff:)?({src_ip}[A-Fa-f:\d.]+)\]\s{0,100}\d{1,100}\(({realm}[^\)]+)\)\s{0,100}\[({role}[^\]]+)\]""",
    """PulseSecure:.*?\[(::ffff:)?({src_ip}[a-fA-F:\d.]+)\]\s{1,100}(({domain}[^\\]+)\\)?(?:({user_email}[^@\s]+@[^@\s]+)|({user}[^\s]+))\(({realm}[^\)]+)?""",
    """\WRequest:\s{0,100}({method}[^\s"]+)\s{1,100}({uri_path}\/[^",\s]*)""",
    """\WHost:\s{0,100}({web_domain}[^\s",:]+)""",
    """\WHost:\s{0,100}[^\s",:]*?({top_domain}(?!(?:\d{1,100}\.){3}\d{1,100})[^\.\s\/:]+(?=(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|tr))+(\s|\/|:|,|$))[^\s\/:",]+)""",
    """\w+\s{1,100}\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}(::ffff:)?({firewall}[A-Fa-f:\d.]+)\s""",
  ]
}
```