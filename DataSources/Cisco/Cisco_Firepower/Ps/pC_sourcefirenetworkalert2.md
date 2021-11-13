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
    """({host}[\w\.-]{1,2000})\s{1,100}SFIMS:""",
    """Protocol:\s{0,100}(Unknown|({protocol}[^,]{1,2000}))""",
    """"({alert_name}[^"]{1,2000})"\s{0,100}\[Classification:\s{0,100}(Unknown|({alert_type}[^\]]{1,2000}))""",
    """User:\s{0,100}(Unknown|({user}[^,]{1,2000}))""",
    """Interface Ingress:\s{0,100}(Unknown|({ingress_interface}[^,]{1,2000}))""",
    """Interface Egress:\s{0,100}(Unknown|({egress_interface}[^,]{1,2000}))""",
    """Security Zone Ingress:\s{0,100}(Unknown|({ingress_zone}[^,]{1,2000}))""",
    """Security Zone Egress:\s{0,100}(Unknown|({egress_zone}[^,]{1,2000}))""",
    """(0.0.0.0|({src_ip}[A-Fa-f:\d.]{1,2000}?)):({src_port}\d{1,100})\s{0,100}->\s{0,100}(0.0.0.0|({dest_ip}[A-Fa-f:\d.]{1,2000}?)):({dest_port}\d{1,100})""",
  ]


}
```