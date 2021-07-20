#### Parser Content
```Java
{
Name = s-estreamer-network-connection-1
  Vendor = Cisco
  Product = Cisco Firepower
  Lms = Splunk
  DataType = "network-connection"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ SFIMS: """, """Protocol:""", """AccessControlRuleName:""", """AccessControlRuleAction:""", """DNSResponseType:""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """({host}[\w\.-]{1,2000})\s{1,100}SFIMS:""",
    """\WProtocol:\s{0,100}({protocol}[^,]{1,2000})""",
    """\WSrcIP:\s{0,100}({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """\WDstIP:\s{0,100}({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """\WSrcPort:\s{0,100}({src_port}\d{1,100})""",
    """\WDstPort:\s{0,100}({dest_port}\d{1,100})""",
    """\WIngressZone:\s{0,100}({ingress_zone}[^,]{1,2000})""",
    """\WEgressZone:\s{0,100}({egress_zone}[^,]{1,2000})""",
    """\WPolicy:\s{0,100}({policy}[^,]{1,2000})""",
    """\WConnectType:\s{0,100}({connect_type}[^,]{1,2000})""",
    """\WAccessControlRuleName:\s{0,100}(Unknown|({rule}[^,]{1,2000}))""",
    """\WAccessControlRuleAction:\s{0,100}({outcome}[^,]{1,2000})""",
    """\WUserName:\s{0,100}(No Authentication Required|({user}[^,\s]{1,2000})),""",
    """\WInitiatorPackets:\s{0,100}({initiator_packets}[^,]{1,2000})""",
    """\WResponderPackets:\s{0,100}({responder_packets}[^,]{1,2000})""",
    """\WInitiatorBytes:\s{0,100}({bytes_in}\d{1,100})""",
    """\WResponderBytes:\s{0,100}({bytes_out}\d{1,100})""",
    """\WNAPPolicy:\s{0,100}({nap_policy}[^,]{1,2000})""",
    """\WDNSResponseType:\s{0,100}({response_type}[^,]{1,2000})""",
    """\WTCPFlags:\s{0,100}({tcp_flags}[^,]{1,2000}?)(,|\s{0,100}$)""",
    """\WURLCategory:\s{0,100}(Unknown|({category}[^,]{1,2000}?))(,|\s{0,100}$)""",
    """\WURLReputation:\s{0,100}({reputation}[^,]{1,2000}?)(,|\s{0,100}$)""",
  ]
  DupFields = [ "outcome->action" ]
}
```