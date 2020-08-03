#### Parser Content
```Java
{
Name = cisco-ftd-firewall-5
  DataType = "network-error"
  Conditions = [ """%FTD""", """regular translation creation failed for icmp""" ]
  Fields = ${CiscoParsersTemplates.cisco-ftd-event-1.Fields}[
    """({event_name}regular translation creation failed for icmp)""",
    """src INSIDE:({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\sdst outside:({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})"""
  ]
}
${CiscoParsersTemplates.cisco-ftd-event-1} {
  Name = cisco-ftd-firewall-6
  DataType = "network-connection"
  Conditions = [ """FTD-6-305011""" ]
  Fields = ${CiscoParsersTemplates.cisco-ftd-event-1.Fields}[
    """(FTD-6-305011:\s({event_name}.+translation))""",
    ]
}
${CiscoParsersTemplates.cisco-ftd-event-1} {
  Name = cisco-ftd-firewall-7
  DataType = "vpn-start"
  Conditions = [ """%FTD-6-602303""" ]
  Fields = ${CiscoParsersTemplates.cisco-ftd-event-1.Fields}[
  """(FTD-6-602303: IPSEC:\s({event_name}.+)SA)"""
  ]
}
${CiscoParsersTemplates.cisco-ftd-event-1} {
  Name = cisco-ftd-firewall-8
  DataType = "vpn-end"
  Conditions = [ """%FTD-6-602304""" ]
  Fields = ${CiscoParsersTemplates.cisco-ftd-event-1.Fields}[
  """(FTD-6-602303: IPSEC:\s({event_name}.+)SA)"""
  ]
}
${CiscoParsersTemplates.cisco-ftd-event-1} {
  Name = cisco-ftd-firewall-9
  DataType = "network-connection"
  Conditions = [ """%FTD-6-805001""" ]
  Fields = ${CiscoParsersTemplates.cisco-ftd-event-1.Fields}[
  """(FTD-6-805001:\s({event_name}.+connection))"""
  ]
}

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
    """\sAccessControlRuleReason:\s({outcome}[^,]+)""",
    """\sSrcIP:\s({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """\sDstIP:\s({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """\sSrcPort:\s({src_port}\d+)""",
    """\sDstPort:\s({dest_port}\d+)""",
    """\sProtocol:\s({protocol}[^,]+)""",
    """\sUser:\s*(Unknown|({user}[^,]+))""", 
    """InitiatorBytes:\s*({bytes_out}\d+)""",
    """ResponderBytes:\s*({bytes_in}\d+)""",
    """\sIngressInterface:\s*({ingress_interface}[^,]+?)(,|\s*$)""",
    """\sEgressInterface:\s*({egress_interface}[^,]+?)(,|\s*$)""",
    """\sIPReputationSICategory:\s({alert_type}[^\s]+)""",
  ]
DupFields = ["alert_type -> alert_name"]
}
```