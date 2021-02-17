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
    """\w+\s+\d+ \d\d:\d\d:\d\d ({host}[\w.\-]+)""",
    """({time}\d+-\d+-\d+T\d+:\d+:\d+Z)\s+({host}[\w\-.]+)?\s*(\(|\%)""",
    """SrcIP:\s*({src_ip}[A-Fa-f:\d.]+)""",
    """DstIP:\s*({dest_ip}[A-Fa-f:\d.]+)""",
    """SrcPort:\s*({src_port}\d+)""",
    """DstPort:\s*({dest_port}\d+)""",
    """AccessControlRuleAction:\s*({outcome}[^,]+)""",
    """Protocol:\s*({protocol}[^,]+)""",
    """User:\s*(Unknown|No Authentication Required|({user}[^,\s]+))""",
    """InitiatorBytes:\s*({bytes_out}\d+)""",
    """ResponderBytes:\s*({bytes_in}\d+)""",
    """ACPolicy:\s*({policy}[^,]+)""",
    """DNSQuery:\s*({query}[^,]+)""",
    """DNSQuery:\s*({query}[^,]+\.({top_query}\w+\.(?i)(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za)))""",
    """DNSRecordType:\s*({query_type}.+?)\s\w+[:=.]""",
    """IngressInterface: ({src_interface}[^\s,]+?),""",
    """EgressInterface: ({dest_interface}[^\s,]+?),""",
  ]
}
```