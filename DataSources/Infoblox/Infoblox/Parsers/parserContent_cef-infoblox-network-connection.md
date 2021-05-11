#### Parser Content
```Java
{
Name = cef-infoblox-network-connection
  Vendor = Infoblox
  Product = Infoblox
  Lms = ArcSight
  DataType = "network-connection"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """CEF:""", """|Infoblox|""", """ act="""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """CEF:([^\|]*\|){4}({rule_id}[^\|]+)\|({alert_name}[^\|]+)\|({alert_severity}[^\|]+)""",
    """\w+\s{1,100}\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}({host}[\w\-.]+)\s""",
    """act="({outcome}[^"]+)""",
    """cat="({activity}[^"]+)""",
    """spt=({src_port}\d{1,100})""",
    """dpt=({dest_port}\d{1,100})""",
    """src=({src_ip}[A-Fa-f:\d.]+)""",
    """dst=({dest_ip}[A-Fa-f:\d.]+)""",
    """fqdn=({src_host}[\w\-.]+)""",
  ]
}
```