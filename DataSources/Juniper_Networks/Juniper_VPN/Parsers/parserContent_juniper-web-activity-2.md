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
    """({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}Z)\s{1,100}(::ffff:)?({host}[\w\-.]{1,2000})\s{1,100}PulseSecure:""",
    """PulseSecure:.+?({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)\s{1,100}\-\s{1,100}(::ffff:)?({host}[\w\-.]{1,2000})""",
    """PulseSecure:.*?\[(::ffff:)?({src_ip}[A-Fa-f:\d.]{1,2000})\]\s{0,100}\d{1,100}\(({realm}[^\)]{1,2000})\)\s{0,100}\[({role}[^\]]{1,2000})\]""",
    """PulseSecure:.*?\[(::ffff:)?({src_ip}[a-fA-F:\d.]{1,2000})\]\s{1,100}(({domain}[^\\]{1,2000})\\)?(?:({user_email}[^@\s]{1,2000}@[^@\s]{1,2000})|({user}[^\s]{1,2000}))\(({realm}[^\)]{1,2000})?""",
    """\WRequest:\s{0,100}({method}[^\s"]{1,2000})\s{1,100}({uri_path}\/[^",\s]{0,2000})""",
    """\WHost:\s{0,100}({web_domain}[^\s",:]{1,2000})""",
    """\WHost:\s{0,100}[^\s",:]{0,2000}?({top_domain}(?!(?:\d{1,100}\.){3}\d{1,100})[^\.\s\/:]{1,2000}(?=(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|tr))+(\s|\/|:|,|$))[^\s\/:",]{1,2000})""",
    """\w+\s{1,100}\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}(::ffff:)?({firewall}[A-Fa-f:\d.]{1,2000})\s""",
  ]
}
```