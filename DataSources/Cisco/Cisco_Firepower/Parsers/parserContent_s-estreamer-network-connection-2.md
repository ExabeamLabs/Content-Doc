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
    """({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}\.\d{1,100}Z)\s{1,100}({host}[\w\.-]{1,2000})\s{1,100}FirePower""",
    """\WProtocol(:|=")\s{0,100}({protocol}[^,"]{1,2000})""",
    """\WSrcIP(:|=")\s{0,100}({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """\WDstIP(:|=")\s{0,100}({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """\WSrcPort(:|=")\s{0,100}({src_port}\d{1,100})""",
    """\WDstPort(:|=")\s{0,100}({dest_port}\d{1,100})""",
    """\WIngressZone(:|=")\s{0,100}({ingress_zone}[^,"]{1,2000})""",
    """\WEgressZone(:|=")\s{0,100}({egress_zone}[^,"]{1,2000})""",
    """\WPolicy(:|=")\s{0,100}({policy}[^,"]{1,2000})""",
    """\WAccessControlRuleName(:|=")\s{0,100}(Unknown|({rule}[^,"]{1,2000}))""",
    """\WAccessControlRuleAction(:|=")\s{0,100}({outcome}[^,"]{1,2000})""",
    """\WUser(:|=")\s{0,100}(No Authentication Required|({user}[^,\s"]{1,2000}))"""",
    """\WInitiatorPackets(:|=")\s{0,100}({initiator_packets}[^,"]{1,2000})""",
    """\WResponderPackets(:|=")\s{0,100}({responder_packets}[^,"]{1,2000})""",
    """\WInitiatorBytes(:|=")\s{0,100}({bytes_in}\d{1,100})""",
    """\WResponderBytes(:|=")\s{0,100}({bytes_out}\d{1,100})""",
    """\WNAPPolicy(:|=")\s{0,100}({nap_policy}[^,"]{1,2000})""",
    """\WDNSResponseType(:|=")\s{0,100}({response_type}[^,"]{1,2000})""",
  ]
  DupFields = [ "outcome->action" ]
}
```