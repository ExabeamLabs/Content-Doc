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
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """({host}[\w\.-]+)\s{1,100}SFIMS:""",
    """\WProtocol:\s{0,100}({protocol}[^,]+)""",
    """\WSrcIP:\s{0,100}({src_ip}[A-Fa-f:\d.]+)""",
    """\WDstIP:\s{0,100}({dest_ip}[A-Fa-f:\d.]+)""",
    """\WSrcPort:\s{0,100}({src_port}\d{1,100})""",
    """\WDstPort:\s{0,100}({dest_port}\d{1,100})""",
    """\WIngressZone:\s{0,100}({ingress_zone}[^,]+)""",
    """\WEgressZone:\s{0,100}({egress_zone}[^,]+)""",
    """\WPolicy:\s{0,100}({policy}[^,]+)""",
    """\WConnectType:\s{0,100}({connect_type}[^,]+)""",
    """\WAccessControlRuleName:\s{0,100}(Unknown|({rule}[^,]+))""",
    """\WAccessControlRuleAction:\s{0,100}({outcome}[^,]+)""",
    """\WUserName:\s{0,100}(No Authentication Required|({user}[^,\s]+)),""",
    """\WInitiatorPackets:\s{0,100}({initiator_packets}[^,]+)""",
    """\WResponderPackets:\s{0,100}({responder_packets}[^,]+)""",
    """\WInitiatorBytes:\s{0,100}({bytes_in}\d{1,100})""",
    """\WResponderBytes:\s{0,100}({bytes_out}\d{1,100})""",
    """\WNAPPolicy:\s{0,100}({nap_policy}[^,]+)""",
    """\WDNSResponseType:\s{0,100}({response_type}[^,]+)""",
    """\WTCPFlags:\s{0,100}({tcp_flags}[^,]+?)(,|\s{0,100}$)""",
    """\WURLCategory:\s{0,100}(Unknown|({category}[^,]+?))(,|\s{0,100}$)""",
    """\WURLReputation:\s{0,100}({reputation}[^,]+?)(,|\s{0,100}$)""",
  ]
  DupFields = [ "outcome->action" ]
}
```