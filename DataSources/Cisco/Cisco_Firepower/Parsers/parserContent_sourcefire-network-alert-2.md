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
    """({host}[\w\.-]+)\s{1,100}SFIMS:""",
    """Protocol:\s{0,100}(Unknown|({protocol}[^,]+))""",
    """"({alert_name}[^"]+)"\s{0,100}\[Classification:\s{0,100}(Unknown|({alert_type}[^\]]+))""",
    """User:\s{0,100}(Unknown|({user}[^,]+))""",
    """Interface Ingress:\s{0,100}(Unknown|({ingress_interface}[^,]+))""",
    """Interface Egress:\s{0,100}(Unknown|({egress_interface}[^,]+))""",
    """Security Zone Ingress:\s{0,100}(Unknown|({ingress_zone}[^,]+))""",
    """Security Zone Egress:\s{0,100}(Unknown|({egress_zone}[^,]+))""",
    """(0.0.0.0|({src_ip}[A-Fa-f:\d.]+?)):({src_port}\d{1,100})\s{0,100}->\s{0,100}(0.0.0.0|({dest_ip}[A-Fa-f:\d.]+?)):({dest_port}\d{1,100})""",
  ]
}
```