#### Parser Content
```Java
{
Name = cef-juniper-account-deleted
  Vendor = Juniper VPN
  Product = Juniper VPN
  Lms = ArcSight
  DataType = "account-deleted"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|Juniper|""", """|User deleted|""" ]
  Fields = [
	"""\Wrt=({time}\d+)""",
	"""\Wdvchost=({host}[\w\-.]+)""",
	"""\Wsrc=({src_ip}[A-Fa-f:\d.]+)""",
	"""\Wsuser=(System|({user}[^\s]+))""",
	"""\Wduser=({target_user}[^\s]+)""",
	"""\Wshost=({src_host}[\w\-.]+)""",
  ]
}
```