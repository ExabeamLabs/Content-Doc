#### Parser Content
```Java
{
Name = cisco-dns-response
  Vendor = Cisco
  Product = Cisco Firepower
  Lms = Direct
  DataType = "dns-response"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """AccessControlRuleAction: """, """ApplicationProtocol: DNS""", """DNSQuery: """ ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """({time}\d+-\d+-\d+T\d+:\d+:\d+Z)\s+({host}[\w\-.]+)?\s*(\(|\%)""",
    """SrcIP:\s*({src_ip}[A-Fa-f:\d.]+)""",
    """DstIP:\s*({dest_ip}[A-Fa-f:\d.]+)""",
    """SrcPort:\s*({src_port}\d+)""",
    """DstPort:\s*({dest_port}\d+)""",
    """AccessControlRuleAction:\s*({outcome}[^,]+)""",
    """Protocol:\s*({protocol}[^,]+)""",
    """User:\s*(Unknown|({user}[^,\s]+))""",
    """InitiatorBytes:\s*({bytes_out}\d+)""",
    """ResponderBytes:\s*({bytes_in}\d+)""",
    """ACPolicy:\s*({policy}[^,]+)""",
    """DNSQuery:\s*({query}[^,]+)""",
    """DNSRecordType:\s*({query_type}[^,]+?)\s*(,|$)""",
  ]
}
```