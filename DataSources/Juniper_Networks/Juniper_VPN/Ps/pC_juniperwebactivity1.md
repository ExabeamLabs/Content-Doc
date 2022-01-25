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
	  """\s{1,100}({host}[\w\-.]{1,2000})\s{1,100}PulseSecure:""",
	  """\Wtime="({time}\d{1,100}-\d{1,100}-\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100})""",
    """\Wuser=({user}[^\s"]{1,2000})""",
    """\Wproto=({protocol}[^\s"]{1,2000})""",
    """\Wsrc=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Wfw=({firewall}[A-Fa-f:\d.]{1,2000})""",
	  """\Wrealm="({realm}[^"]{1,2000})""",
	  """\Wroles="({role}[^"]{1,2000})""",
    """\WRequest:\s{0,100}({method}[^\s"]{1,2000})\s{1,100}({uri_path}\/[^",\s]{0,2000})""",
    """\WHost:\s{0,100}({web_domain}[^\s",:]{1,2000})""",
  ]


}
```