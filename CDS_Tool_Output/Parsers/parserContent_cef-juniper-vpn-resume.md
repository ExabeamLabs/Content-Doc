#### Parser Content
```Java
{
Name = cef-juniper-vpn-resume
  Vendor = Juniper VPN
  Product = Juniper VPN
  Lms = ArcSight
  DataType = "access-control"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|Juniper|""", """|Session resumed|""" ]
  Fields = [
	"""\Wrt=({time}\d+)""",
	"""\Wdvchost=({host}[\w\-.]+)""",
	"""\Wsrc=({src_ip}[A-Fa-f:\d.]+)""",
	"""\Wsuser=(System|({user}[^\s]+))""",
	"""\Wshost=({src_host}[\w\-.]+)""",
    """\Wsproc=({realm}.+?)\s+\w+=""",
    """\Wspriv=({resource}.+?)\s+\w+=""",
    """({event_code}Session resumed)""",
  ]
  DupFields = [ "host->dest_host" ]
}
```