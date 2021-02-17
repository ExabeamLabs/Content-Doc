#### Parser Content
```Java
{
Name = s-estreamer-network-connection-2
  Vendor = Cisco
  Product = Cisco Firepower
  Lms = Splunk
  DataType = "network-connection"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
  Conditions = [ """ FirePower """, """Protocol="""", """AccessControlRuleName="""", """AccessControlRuleAction="""" ]
  Fields = [
    """({time}\d+-\d+-\d+T\d+:\d+:\d+\.\d+Z)\s+({host}[\w\.-]+)\s+FirePower""",
    """\WProtocol(:|=")\s*({protocol}[^,"]+)""",
    """\WSrcIP(:|=")\s*({src_ip}[A-Fa-f:\d.]+)""",
    """\WDstIP(:|=")\s*({dest_ip}[A-Fa-f:\d.]+)""",
    """\WSrcPort(:|=")\s*({src_port}\d+)""",
    """\WDstPort(:|=")\s*({dest_port}\d+)""",
    """\WIngressZone(:|=")\s*({ingress_zone}[^,"]+)""",
    """\WEgressZone(:|=")\s*({egress_zone}[^,"]+)""",
    """\WPolicy(:|=")\s*({policy}[^,"]+)""",
    """\WAccessControlRuleName(:|=")\s*(Unknown|({rule}[^,"]+))""",
    """\WAccessControlRuleAction(:|=")\s*({outcome}[^,"]+)""",
    """\WUser(:|=")\s*(No Authentication Required|({user}[^,\s"]+))"""",
    """\WInitiatorPackets(:|=")\s*({initiator_packets}[^,"]+)""",
    """\WResponderPackets(:|=")\s*({responder_packets}[^,"]+)""",
    """\WInitiatorBytes(:|=")\s*({bytes_in}\d+)""",
    """\WResponderBytes(:|=")\s*({bytes_out}\d+)""",
    """\WNAPPolicy(:|=")\s*({nap_policy}[^,"]+)""",
    """\WDNSResponseType(:|=")\s*({response_type}[^,"]+)""",
  ]
  DupFields = [ "outcome->action" ]
}
```