#### Parser Content
```Java
{
Name = sourcefire-network-alert-3
  Vendor = Cisco
  Product = Cisco Firepower
  Lms = Direct
  DataType = "network-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """IngressInterface:""", """ACPolicy:""", """IntrusionPolicy:""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ) ({host}[\w.\-]{1,2000})""",
    """\sSrcIP:\s{0,100}({src_ip}[a-fA-F\d.:]{1,2000})""",
    """\sDstIP:\s{0,100}({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """\sSrcPort:\s{0,100}({src_port}\d{1,100})""",
    """\sDstPort:\s{0,100}({dest_port}\d{1,100})""",
    """\sProtocol:\s{0,100}({protocol}[^,]{1,2000}?)(,|\s{0,100}$)""",
    """\sUser:\s{0,100}(Unknown|({user}[^,]{1,2000}?))(,|\s{0,100}$)""",
    """\sIngressInterface:\s{0,100}({ingress_interface}[^,]{1,2000}?)(,|\s{0,100}$)""",
    """\sEgressInterface:\s{0,100}({egress_interface}[^,]{1,2000}?)(,|\s{0,100}$)""",
    """\sClassification:\s{0,100}({alert_type}[^,]{1,2000}?)(,|\s{0,100}$)""",
    """\sIntrusionPolicy:\s{0,100}({alert_name}[^,]{1,2000}?)(,|\s{0,100}$)""",
  ]
}
```