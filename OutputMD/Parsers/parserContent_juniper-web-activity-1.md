#### Parser Content
```Java
{
Name = juniper-web-activity-1
  Vendor = Juniper VPN
  Product = Juniper VPN
  Lms = Direct
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ PulseSecure:""", """ Host: """, """, Request: """, """user=""" ]
  Fields = [
	  """\s+({host}[\w\-.]+)\s+PulseSecure:""",
	  """\Wtime="({time}\d+-\d+-\d+\s+\d+:\d+:\d+)""",
    """\Wuser=({user}[^\s"]+)""",
    """\Wproto=({protocol}[^\s"]+)""",
    """\Wsrc=({src_ip}[A-Fa-f:\d.]+)""",
    """\Wfw=({firewall}[A-Fa-f:\d.]+)""",
	  """\Wrealm="({realm}[^"]+)""",
	  """\Wroles="({role}[^"]+)""",
    """\WRequest:\s*({method}[^\s"]+)\s+({uri_path}\/[^",\s]*)""",
    """\WHost:\s*({web_domain}[^\s",:]+)""",
    """\WHost:\s*[^\s",:]*?({top_domain}(?!(?:\d+\.){3}\d+)[^\.\s\/:]+(?=(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|tr))+(\s|\/|:|,|$))[^\s\/:",]+)""",
  ]
}
```