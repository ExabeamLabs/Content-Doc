#### Parser Content
```Java
{
Name = cef-infoblox-network-alert
  Vendor = Infoblox
  Product = Infoblox
  Lms = ArcSight
  DataType = "network-connection"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """CEF:""", """|Infoblox|""", """ act="ALERT""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """CEF:([^\|]*\|){4}({rule_id}[^\|]+)\|({alert_name}[^\|]+)\|({alert_severity}[^\|]+)""",
    """\w+\s+\d+\s+\d+:\d+:\d+\s+({host}[\w\-.]+)\s""",
    """act="({outcome}[^"]+)""",
    """cat="({activity}[^"]+)""",
    """spt=({src_port}\d+)""",
    """dpt=({dest_port}\d+)""",
    """src=({src_ip}[A-Fa-f:\d.]+)""",
    """dst=({dest_ip}[A-Fa-f:\d.]+)""",
    """fqdn=({src_host}[\w\-.]+)""",
  ]
}
```