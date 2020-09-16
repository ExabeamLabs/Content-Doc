#### Parser Content
```Java
{
Name = cef-juniper-vpn-timeout-1
  Vendor = Juniper Networks
  Product = Juniper VPN
  Lms = ArcSight
  DataType = "vpn-end"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|Juniper|""", """|Session timed out|""" ]
  Fields = [
	"""\Wrt=({time}\d+)""",
	"""\Wdvchost=({host}[\w\-.]+)""",
	"""\Wsrc=({src_ip}[A-Fa-f:\d.]+)""",
	"""\Wsuser=(System|({user}[^\s]+))""",
    """\Wsproc=({realm}.+?)\s+\w+=""",
  ]
  DupFields = [ "host->dest_host" ]
}
```