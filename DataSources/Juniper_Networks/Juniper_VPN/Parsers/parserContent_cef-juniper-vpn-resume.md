#### Parser Content
```Java
{
Name = cef-juniper-vpn-resume
  Vendor = Juniper Networks
  Product = Juniper VPN
  Lms = ArcSight
  DataType = "access-control"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|Juniper|""", """|Session resumed|""" ]
  Fields = [
	"""\Wrt=({time}\d{1,100})""",
	"""\Wdvchost=({host}[\w\-.]+)""",
	"""\Wsrc=({src_ip}[A-Fa-f:\d.]+)""",
	"""\Wsuser=(System|({user}[^\s]+))""",
	"""\Wshost=({src_host}[\w\-.]+)""",
    """\Wsproc=({realm}.+?)\s{1,100}\w+=""",
    """\Wspriv=({resource}.+?)\s{1,100}\w+=""",
    """({event_code}Session resumed)""",
    """dst=({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""", 
  ]
  DupFields = [ "host->dest_host" , "user->account"]
}
```