#### Parser Content
```Java
{
Name = cef-juniper-vpn-close-1
  Vendor = Juniper VPN
  Product = Juniper VPN
  Lms = ArcSight
  DataType = "vpn-end"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|Juniper|""", """|Connection closed|""", """|Connection closed by user|""" ]
  Fields = [
	"""\Wrt=({time}\d+)""",
	"""\Wdvchost=({host}[\w\-.]+)""",
	"""\Wdst=({dest_ip}[A-Fa-f:\d.]+)""",
	"""\Wdhost=({dest_host}[\w\-.]+)""",
  ]
}
```