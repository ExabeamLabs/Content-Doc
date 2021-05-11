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
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ) ({host}[\w.\-]+)""",
    """\sSrcIP:\s{0,100}({src_ip}[a-fA-F\d.:]+)""",
    """\sDstIP:\s{0,100}({dest_ip}[a-fA-F\d.:]+)""",
    """\sSrcPort:\s{0,100}({src_port}\d{1,100})""",
    """\sDstPort:\s{0,100}({dest_port}\d{1,100})""",
    """\sProtocol:\s{0,100}({protocol}[^,]+?)(,|\s{0,100}$)""",
    """\sUser:\s{0,100}(Unknown|({user}[^,]+?))(,|\s{0,100}$)""",
    """\sIngressInterface:\s{0,100}({ingress_interface}[^,]+?)(,|\s{0,100}$)""",
    """\sEgressInterface:\s{0,100}({egress_interface}[^,]+?)(,|\s{0,100}$)""",
    """\sClassification:\s{0,100}({alert_type}[^,]+?)(,|\s{0,100}$)""",
    """\sIntrusionPolicy:\s{0,100}({alert_name}[^,]+?)(,|\s{0,100}$)""",
  ]
}
```