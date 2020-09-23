#### Parser Content
```Java
{
Name = n-forwarded-cef-juniper-vpn-start-2
  Product = Juniper VPN
DataType = "vpn-start"
Conditions = [ "CEF:", "|McAfee|", "|SecureAccess", "VPN Tunneling session started for user" ]
}

{
  Name = cef-juniper-proxy
  Vendor = Juniper Networks
  Product = Juniper VPN
  Lms = ArcSight
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|Juniper|""", """|Web request completed|""", """WebRequest completed""" ]
  Fields = [
	"""\Wrt=({time}\d+)""",
	"""\Wdvchost=({host}[\w\-.]+)""",
	"""\Wresult\\=({result_code}\d+)""",
	"""\Wsent\\=({bytes_out}\d+)""",
	"""\Wreceived\\=({bytes_in}\d+)""",
	"""\Wsrc=({src_ip}[A-Fa-f:\d.]+)""",
	"""\Wdst=({dest_ip}[A-Fa-f:\d.]+)""",
	"""\Wsuser=(System|({user}[^\s]+))""",
	"""\Wrequest=({full_url}(({protocol}[\w]+):\/+)?({web_domain}[^\s:\\\/]+)(:({dest_port}\d+)\/+)?({uri_path}\/[^\s\?]+)?({uri_query}\?[^\s]+)?)\s+([\w\\]+=|$)""",
	"""\Wrequest=(.*?)({top_domain}(?!(?:\d+\.){3}\d+)[^\.\s\/:]+(?=(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|tr))+(\s|\/|:|$))[^\s\/:]+)""",
	"""\WrequestMethod=({method}[^\s]+)""",
	"""\Wcn1=({category}[^\s]+)""",
  ]
}
```