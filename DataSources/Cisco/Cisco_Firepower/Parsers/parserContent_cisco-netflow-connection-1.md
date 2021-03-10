#### Parser Content
```Java
{
Name = cisco-netflow-connection-1
  Vendor = Cisco
  Product = Cisco Firepower
  Lms = Direct
  DataType = "netflow-connection"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """AccessControlRuleAction: """, """IngressInterface: """, """AccessControlRuleName: """, """InitiatorPackets: """ ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """({time}\d+-\d+-\d+T\d+:\d+:\d+Z)\s+({host}[\w\-.]+)?\s*(\(|\%)""",
    """SrcIP:\s*({src_ip}[A-Fa-f:\d.]+)""",
    """DstIP:\s*({dest_ip}[A-Fa-f:\d.]+)""",
    """SrcPort:\s*({src_port}\d+)""",
    """DstPort:\s*({dest_port}\d+)""",
    """AccessControlRuleAction:\s*({outcome}[^,]+)""",
    """Protocol:\s*({protocol}[^,]+)""",
    """IngressInterface:\s*({src_interface}[^,]+)""",
    """EgressInterface:\s*({dest_interface}[^,]+)""",
    """ACPolicy:\s*({policy}[^,]+)""",
    """AccessControlRuleName:\s*({rule}[^,]+)""",
    """User:\s*(Unknown|({user}[^,\s]+))""",
    """ConnectionDuration:\s*({connection_duration}[^,]+)""",
    """InitiatorPackets:\s*({packets_in}\d+)""",
    """ResponderPackets:\s*({packets_out}\d+)""",
  ]
}
```