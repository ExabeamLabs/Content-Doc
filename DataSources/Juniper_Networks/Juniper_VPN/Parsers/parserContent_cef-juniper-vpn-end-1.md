#### Parser Content
```Java
{
Name = cef-juniper-vpn-end-1
  Vendor = Juniper VPN
  Product = Juniper VPN
  Lms = ArcSight
  DataType = "vpn-end"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|Juniper|""", """|Connection not authenticated yet|""" ]
  Fields = [
	"""\Wrt=({time}\d+)""",
	"""\Wdvchost=({host}[\w\-.]+)""",
	"""\Wdhost=({dest_host}[\w\-.]+)""",
	"""\Wsrc=({src_ip}[A-Fa-f:\d.]+)""",
	"""\Wdst=({dest_ip}[A-Fa-f:\d.]+)""",
	"""\Wsuser=(System|({user}[^\s]+))""",
	"""\Wshost=({src_host}[\w\-.]+)""",
    """\Wmsg=({additional_info}.+?)\s+end=""",
  ]
}
```