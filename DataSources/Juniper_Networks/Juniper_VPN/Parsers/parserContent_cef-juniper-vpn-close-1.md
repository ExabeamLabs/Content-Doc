#### Parser Content
```Java
{
Name = cef-juniper-vpn-close-1
  Vendor = Juniper Networks
  Product = Juniper VPN
  Lms = ArcSight
  DataType = "vpn-end"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|Juniper|""", """|Connection closed|""", """|Connection closed by user|""" ]
  Fields = [
	"""\Wrt=({time}\d{1,100})""",
	"""\Wdvchost=({host}[\w\-.]{1,2000})""",
	"""\Wdst=({dest_ip}[A-Fa-f:\d.]{1,2000})""",
	"""\Wdhost=({dest_host}[\w\-.]{1,2000})""",
  ]
}
```