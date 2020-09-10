#### Parser Content
```Java
{
Name = firepower-dns-response
  Vendor = Cisco
  Product = Cisco Firepower
  Lms = Direct
  DataType = "dns-response"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """DNSSICategory: """, """DNS_Sinkhole: """ ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)""",
    """\sAccessControlRuleReason:\s({outcome}[^,]+)""",
    """\sSrcIP:\s({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """\sDstIP:\s({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """\sSrcPort:\s({src_port}\d+)""",
    """\sDstPort:\s({dest_port}\d+)""",
    """\sProtocol:\s({protocol}[^,]+)""",
    """\sIngressInterface:\s*({ingress_interface}[^,]+)""",
    """\sEgressInterface:\s*({egress_interface}[^,]+)""",
    """\sUser:\s*(Unknown|({user}[^,]+))""",
    """InitiatorBytes:\s*({bytes_out}\d+)""",
    """ResponderBytes:\s*({bytes_in}\d+)""",
    """\sDNSQuery:\s*({query}[^,]+)""",
    """\sDNSRecordType:\s*({query_type}[^,]+)""",
    """\sDNSSICategory:\s({alert_type}[^\s]+)""",
  ]
   DupFields = ["alert_type -> alert_name"]
}
```