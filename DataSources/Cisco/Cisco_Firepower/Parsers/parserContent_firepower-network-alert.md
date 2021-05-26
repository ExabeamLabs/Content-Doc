#### Parser Content
```Java
{
Name = firepower-network-alert
  Vendor = Cisco
  Product = Cisco Firepower
  Lms = Direct
  DataType = "network-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """IPReputationSICategory:""", """AccessControlRuleAction: """ ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)""",
    """\sAccessControlRuleReason:\s({outcome}[^,]{1,2000})""",
    """\sSrcIP:\s({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """\sDstIP:\s({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """\sSrcPort:\s({src_port}\d{1,100})""",
    """\sDstPort:\s({dest_port}\d{1,100})""",
    """\sProtocol:\s({protocol}[^,]{1,2000})""",
    """\sUser:\s{0,100}(Unknown|({user}[^,]{1,2000}))""", 
    """InitiatorBytes:\s{0,100}({bytes_out}\d{1,100})""",
    """ResponderBytes:\s{0,100}({bytes_in}\d{1,100})""",
    """\sIngressInterface:\s{0,100}({ingress_interface}[^,]{1,2000}?)(,|\s{0,100}$)""",
    """\sEgressInterface:\s{0,100}({egress_interface}[^,]{1,2000}?)(,|\s{0,100}$)""",
    """\sIPReputationSICategory:\s({alert_type}[^\s]{1,2000})""",
  ]
DupFields = ["alert_type -> alert_name"]
}
```