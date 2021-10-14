#### Parser Content
```Java
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
	"""\Wrt=({time}\d{1,100})""",
	"""\Wdvchost=({host}[\w\-.]{1,2000})""",
	"""\Wresult\\=({result_code}\d{1,100})""",
	"""\Wsent\\=({bytes_out}\d{1,100})""",
	"""\Wreceived\\=({bytes_in}\d{1,100})""",
	"""\Wsrc=({src_ip}[A-Fa-f:\d.]{1,2000})""",
	"""\Wdst=({dest_ip}[A-Fa-f:\d.]{1,2000})""",
	"""\Wsuser=(System|({user}[^\s]{1,2000}))""",
	"""\Wrequest=({full_url}(({protocol}[\w]{1,2000}):\/+)?({web_domain}[^\s:\\\/]{1,2000})(:({dest_port}\d{1,100})\/+)?({uri_path}\/[^\s\?]{1,2000})?({uri_query}\?[^\s]{1,2000})?)\s{1,100}([\w\\]{1,2000}=|$)""",
	"""\WrequestMethod=({method}[^\s]{1,2000})""",
	"""\Wcn1=({category}[^\s]{1,2000})""",
  ]
}
```