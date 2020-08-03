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
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """({host}[\w\.-]+)\s+SFIMS:""",
    """\WProtocol:\s*({protocol}[^,]+)""",
    """\WSrcIP:\s*({src_ip}[A-Fa-f:\d.]+)""",
    """\WDstIP:\s*({dest_ip}[A-Fa-f:\d.]+)""",
    """\WSrcPort:\s*({src_port}\d+)""",
    """\WDstPort:\s*({dest_port}\d+)""",
    """\WIngressZone:\s*({ingress_zone}[^,]+)""",
    """\WEgressZone:\s*({egress_zone}[^,]+)""",
    """\WPolicy:\s*({policy}[^,]+)""",
    """\WConnectType:\s*({connect_type}[^,]+)""",
    """\WAccessControlRuleName:\s*(Unknown|({rule}[^,]+))""",
    """\WAccessControlRuleAction:\s*({outcome}[^,]+)""",
    """\WUserName:\s*(No Authentication Required|({user}[^,\s]+)),""",
    """\WInitiatorPackets:\s*({initiator_packets}[^,]+)""",
    """\WResponderPackets:\s*({responder_packets}[^,]+)""",
    """\WInitiatorBytes:\s*({bytes_in}\d+)""",
    """\WResponderBytes:\s*({bytes_out}\d+)""",
    """\WNAPPolicy:\s*({nap_policy}[^,]+)""",
    """\WDNSResponseType:\s*({response_type}[^,]+)""",
    """\WTCPFlags:\s*({tcp_flags}[^,]+?)(,|\s*$)""",
    """\WURLCategory:\s*(Unknown|({category}[^,]+?))(,|\s*$)""",
    """\WURLReputation:\s*({reputation}[^,]+?)(,|\s*$)""",
  ]
  DupFields = [ "outcome->action" ]
}
```