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
	"""\Wrt=({time}\d+)""",
	"""\Wdvchost=({host}[\w\-.]+)""",
	"""\Wsrc=({src_ip}[A-Fa-f:\d.]+)""",
	"""\Wdst=({dest_ip}[A-Fa-f:\d.]+)""",
	"""\Wsuser=(System|({user}[^\s]+))""",
	"""\Wshost=({src_host}[\w\-.]+)""",
    """\Wafter\s+({session_duration}\d+)\s+seconds""",
    """\Wwith\s+({bytes_in}\d+)\s+bytes read""",
    """\Wand\s+({bytes_out}\d+)\s+bytes written"""
    """\Wmsg=({additional_info}.+?)\s+end=""",
    """Closed connection to=({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
  ]
  DupFields = [ "host->dest_host" ]
}
```