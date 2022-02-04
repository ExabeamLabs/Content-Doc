#### Parser Content
```Java
{
Name = checkpoint-network-connection-accept-2
  Vendor = Check Point
  Product = NGFW
  Lms = Direct
  DataType = "network-connection"
  TimeFormat = "epoch_sec"
  Conditions = [ """ CheckPoint """, """action:Accept""", """product:VPN-1 & FireWall-1""" ]
  Fields = [
    """\stime:({time}\d{1,100})"""",
    """\d\d:\d\d:\d\dZ\s{0,100}({host}[\w\-\.]{1,2000})\s{0,100}CheckPoint""",
    """cu_rule_category:({activity}[^"]{1,2000})"""",
    """event_name:({event_name}[^"]{1,2000})"""",
    """cu_rule_id:\{({rule_id}[^"]{1,2000}?)\}"""",
    """cu_detected_by:({src_ip}[A-Fa-f\d\.:]{1,2000})"""",
    """dst:({dest_ip}[A-Fa-f\d\.:]{1,2000})"""",
    """action:({outcome}Accept)""",
    """proto:({protocol}[^"]{1,2000})"""",
    """service:({dest_port}[^"]{1,2000})"""",
    """ifdir:({direction}[^"]{1,2000})""""
  ]


}
```