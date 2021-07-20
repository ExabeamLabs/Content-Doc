#### Parser Content
```Java
{
Name = cef-juniper-vpn-end-1
  Vendor = Juniper Networks
  Product = Juniper VPN
  Lms = ArcSight
  DataType = "vpn-end"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|Juniper|""", """|Connection not authenticated yet|""" ]
  Fields = [
	"""\Wrt=({time}\d{1,100})""",
	"""\Wdvchost=({host}[\w\-.]{1,2000})""",
	"""\Wdhost=({dest_host}[\w\-.]{1,2000})""",
	"""\Wsrc=({src_ip}[A-Fa-f:\d.]{1,2000})""",
	"""\Wdst=({dest_ip}[A-Fa-f:\d.]{1,2000})""",
	"""\Wsuser=(System|({user}[^\s]{1,2000}))""",
	"""\Wshost=({src_host}[\w\-.]{1,2000})""",
    """\Wmsg=({additional_info}.+?)\s{1,100}end=""",
  ]
}
```