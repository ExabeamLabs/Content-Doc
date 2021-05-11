#### Parser Content
```Java
{
Name = juniper-web-activity-1
  Vendor = Juniper Networks
  Product = Juniper VPN
  Lms = Direct
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ PulseSecure:""", """ Host: """, """, Request: """, """user=""" ]
  Fields = [
	  """\s{1,100}({host}[\w\-.]+)\s{1,100}PulseSecure:""",
	  """\Wtime="({time}\d{1,100}-\d{1,100}-\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100})""",
    """\Wuser=({user}[^\s"]+)""",
    """\Wproto=({protocol}[^\s"]+)""",
    """\Wsrc=({src_ip}[A-Fa-f:\d.]+)""",
    """\Wfw=({firewall}[A-Fa-f:\d.]+)""",
	  """\Wrealm="({realm}[^"]+)""",
	  """\Wroles="({role}[^"]+)""",
    """\WRequest:\s{0,100}({method}[^\s"]+)\s{1,100}({uri_path}\/[^",\s]*)""",
    """\WHost:\s{0,100}({web_domain}[^\s",:]+)""",
    """\WHost:\s{0,100}[^\s",:]*?({top_domain}(?!(?:\d{1,100}\.){3}\d{1,100})[^\.\s\/:]+(?=(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|tr))+(\s|\/|:|,|$))[^\s\/:",]+)""",
  ]
}
```