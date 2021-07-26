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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}Z)\s{1,100}({host}[\w\-.]{1,2000})?\s{0,100}(\(|\%)""",
    """SrcIP:\s{0,100}({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """DstIP:\s{0,100}({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """SrcPort:\s{0,100}({src_port}\d{1,100})""",
    """DstPort:\s{0,100}({dest_port}\d{1,100})""",
    """AccessControlRuleAction:\s{0,100}({outcome}[^,]{1,2000})""",
    """Protocol:\s{0,100}({protocol}[^,]{1,2000})""",
    """IngressInterface:\s{0,100}({src_interface}[^,]{1,2000})""",
    """EgressInterface:\s{0,100}({dest_interface}[^,]{1,2000})""",
    """ACPolicy:\s{0,100}({policy}[^,]{1,2000})""",
    """AccessControlRuleName:\s{0,100}({rule}[^,]{1,2000})""",
    """User:\s{0,100}(Unknown|No Authentication Required|({user}[^,\s]{1,2000}))""", 
    """ConnectionDuration:\s{0,100}({connection_duration}[^,]{1,2000})""",
    """InitiatorPackets:\s{0,100}({packets_in}\d{1,100})""",
    """ResponderPackets:\s{0,100}({packets_out}\d{1,100})""",
    """InitiatorBytes:\s{0,100}({bytes_in}\d{1,100})""",
    """ResponderBytes:\s{0,100}({bytes_out}\d{1,100})""",
  ]
}
```