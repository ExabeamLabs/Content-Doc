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
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """\w+\s{1,100}\d{1,100} \d\d:\d\d:\d\d ({host}[\w.\-]+)""",
    """({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}Z)\s{1,100}({host}[\w\-.]+)?\s{0,100}(\(|\%)""",
    """SrcIP:\s{0,100}({src_ip}[A-Fa-f:\d.]+)""",
    """DstIP:\s{0,100}({dest_ip}[A-Fa-f:\d.]+)""",
    """SrcPort:\s{0,100}({src_port}\d{1,100})""",
    """DstPort:\s{0,100}({dest_port}\d{1,100})""",
    """AccessControlRuleAction:\s{0,100}({outcome}[^,]+)""",
    """Protocol:\s{0,100}({protocol}[^,]+)""",
    """User:\s{0,100}(Unknown|No Authentication Required|({user}[^,\s]+))""",
    """InitiatorBytes:\s{0,100}({bytes_out}\d{1,100})""",
    """ResponderBytes:\s{0,100}({bytes_in}\d{1,100})""",
    """ACPolicy:\s{0,100}({policy}[^,]+)""",
    """DNSQuery:\s{0,100}({query}[^,]+)""",
    """DNSQuery:\s{0,100}({query}[^,]+\.({top_query}\w+\.(?i)(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za)))""",
    """DNSRecordType:\s{0,100}({query_type}.+?)\s\w+[:=.]""",
    """IngressInterface: ({src_interface}[^\s,]+?),""",
    """EgressInterface: ({dest_interface}[^\s,]+?),""",
  ]
}
```