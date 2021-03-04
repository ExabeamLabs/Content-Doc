#### Parser Content
```Java
{
Name = cef-juniper-vpn-authfailed
  Vendor = Juniper VPN
  Product = Juniper VPN
  Lms = ArcSight
  DataType = "authentication-failed"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|Juniper|""", """|Primary authentication failed|""" ]
  Fields = [
	"""\Wrt=({time}\d+)""",
	"""\Wdvchost=({host}[\w\-.]+)""",
    """({failure_reason}(Primary|Secondary) authentication failed) for\s+(({domain}[^\\]+)\\+)?({user}[^@\s\\\/]+)(\/({realm}.+?))\s+from=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
	"""\Wsrc=({src_ip}[A-Fa-f:\d.]+)""",
	"""\Wsuser=(System|({user}[^\s]+))""",
  ]
  DupFields = [ "host->dest_host" ]
}
```