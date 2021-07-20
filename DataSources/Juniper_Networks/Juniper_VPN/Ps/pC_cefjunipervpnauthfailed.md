#### Parser Content
```Java
{
Name = cef-juniper-vpn-authfailed
  Vendor = Juniper Networks
  Product = Juniper VPN
  Lms = ArcSight
  DataType = "authentication-failed"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|Juniper|""", """|Primary authentication failed|""" ]
  Fields = [
	"""\Wrt=({time}\d{1,100})""",
	"""\Wdvchost=({host}[\w\-.]{1,2000})""",
    """({failure_reason}(Primary|Secondary) authentication failed) for\s{1,100}(({domain}[^\\]{1,2000})\\+)?({user}[^@\s\\\/]{1,2000})(\/({realm}.+?))\s{1,100}from=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
	"""\Wsrc=({src_ip}[A-Fa-f:\d.]{1,2000})""",
	"""\Wsuser=(System|({user}[^\s]{1,2000}))""",
  ]
  DupFields = [ "host->dest_host" ]
}
```