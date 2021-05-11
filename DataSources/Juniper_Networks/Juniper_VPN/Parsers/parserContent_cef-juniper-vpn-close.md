#### Parser Content
```Java
{
Name = cef-juniper-vpn-close
  Vendor = Juniper Networks
  Product = Juniper VPN
  Lms = ArcSight
  DataType = "vpn-end"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|Juniper|""", """|Closed connection|""", """ bytes read """, """ bytes written """ ]
  Fields = [
	"""\Wrt=({time}\d{1,100})""",
	"""\Wdvchost=({host}[\w\-.]+)""",
	"""\Wsrc=({src_ip}[A-Fa-f:\d.]+)""",
	"""\Wdst=({dest_ip}[A-Fa-f:\d.]+)""",
	"""\Wsuser=(System|({user}[^\s]+))""",
	"""\Wshost=({src_host}[\w\-.]+)""",
    """\Wafter\s{1,100}({session_duration}\d{1,100})\s{1,100}seconds""",
    """\Wwith\s{1,100}({bytes_in}\d{1,100})\s{1,100}bytes read""",
    """\Wand\s{1,100}({bytes_out}\d{1,100})\s{1,100}bytes written"""
    """\Wmsg=({additional_info}.+?)\s{1,100}end=""",
    """Closed connection to=({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
  ]
  DupFields = [ "host->dest_host" ]
}
```