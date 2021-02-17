#### Parser Content
```Java
{
Name = sourcefire-network-alert-2
  Vendor = Cisco
  Product = Cisco Firepower
  Lms = Direct
  DataType = "network-alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ SFIMS: [""", """, Interface Ingress: """, """, Security Zone Egress: """ ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """({host}[\w\.-]+)\s+SFIMS:""",
    """Protocol:\s*(Unknown|({protocol}[^,]+))""",
    """"({alert_name}[^"]+)"\s*\[Classification:\s*(Unknown|({alert_type}[^\]]+))""",
    """User:\s*(Unknown|({user}[^,]+))""",
    """Interface Ingress:\s*(Unknown|({ingress_interface}[^,]+))""",
    """Interface Egress:\s*(Unknown|({egress_interface}[^,]+))""",
    """Security Zone Ingress:\s*(Unknown|({ingress_zone}[^,]+))""",
    """Security Zone Egress:\s*(Unknown|({egress_zone}[^,]+))""",
    """(0.0.0.0|({src_ip}[A-Fa-f:\d.]+?)):({src_port}\d+)\s*->\s*(0.0.0.0|({dest_ip}[A-Fa-f:\d.]+?)):({dest_port}\d+)""",
  ]
}
```