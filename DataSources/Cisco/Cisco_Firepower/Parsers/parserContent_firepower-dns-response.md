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
    """\sSrcPort:\s({src_port}\d{1,100})""",
    """\sDstPort:\s({dest_port}\d{1,100})""",
    """\sProtocol:\s({protocol}[^,]+)""",
    """\sIngressInterface:\s{0,100}({ingress_interface}[^,]+)""",
    """\sEgressInterface:\s{0,100}({egress_interface}[^,]+)""",
    """\sUser:\s{0,100}(Unknown|({user}[^,]+))""",
    """InitiatorBytes:\s{0,100}({bytes_out}\d{1,100})""",
    """ResponderBytes:\s{0,100}({bytes_in}\d{1,100})""",
    """\sDNSQuery:\s{0,100}({query}[^,]+)""",
    """\sDNSRecordType:\s{0,100}({query_type}[^,]+)""",
    """\sDNSSICategory:\s({alert_type}[^\s]+)""",
  ]
   DupFields = ["alert_type -> alert_name"]
}
```