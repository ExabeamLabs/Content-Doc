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
    """\sSrcIP:\s*({src_ip}[a-fA-F\d.:]+)""",
    """\sDstIP:\s*({dest_ip}[a-fA-F\d.:]+)""",
    """\sSrcPort:\s*({src_port}\d+)""",
    """\sDstPort:\s*({dest_port}\d+)""",
    """\sProtocol:\s*({protocol}[^,]+?)(,|\s*$)""",
    """\sUser:\s*(Unknown|({user}[^,]+?))(,|\s*$)""",
    """\sIngressInterface:\s*({ingress_interface}[^,]+?)(,|\s*$)""",
    """\sEgressInterface:\s*({egress_interface}[^,]+?)(,|\s*$)""",
    """\sClassification:\s*({alert_type}[^,]+?)(,|\s*$)""",
    """\sIntrusionPolicy:\s*({alert_name}[^,]+?)(,|\s*$)""",
  ]
}
```