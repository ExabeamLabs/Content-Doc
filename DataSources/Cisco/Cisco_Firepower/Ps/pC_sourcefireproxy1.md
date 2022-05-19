#### Parser Content
```Java
{
Name = sourcefire-proxy-1
  Vendor = Cisco
  Product = Cisco Firepower
  Lms = Direct
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """Policy: """, """ApplicationProtocol: HTTP""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """\w+\s{1,100}\d{1,100} \d\d:\d\d:\d\d ({host}[\w.\-]{1,2000})""",
    """({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}Z)\s{1,100}({host}[\w\-.]{1,2000})?\s{0,100}(\(|\%)""",
    """({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d)""",
    """SrcIP:\s{0,100}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """DstIP:\s{0,100}({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """DstIP:\s{0,100}({web_domain}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """SrcPort:\s{0,100}({src_port}\d{1,100})""",
    """DstPort:\s{0,100}({dest_port}\d{1,100})""",
    """AccessControlRuleAction:\s{0,100}({action}[^,]{1,2000})""",
    """User:\s{0,100}(Unknown|No Authentication Required|({user}[^,\s]{1,2000}))""",
    """UserAgent:\s{0,100}({user_agent}.+?),\s{0,100}Client:""",
    """Protocol:\s{0,100}({protocol}[^,]{1,2000})""",
    """InitiatorBytes:\s{0,100}({bytes_out}[^,]{1,2000})""",
    """ResponderBytes:\s{0,100}({bytes_in}[^,]{1,2000})""",
    """URLCategory:\s{0,100}({categories}({category}[^,;]{1,2000})[^,]{0,2000})""",
    """URL:\s{0,100}({full_url}\S+?)(,\s{0,100}\w+:|\s)""",
    """URL:\s{0,100}(?:-|\w+:\/+)({web_domain}[^\s\/:]{1,2000})""",
    """URL:\s{0,100}(?:-|\w+:\/+[^\/]{1,2000})({uri_path}\/[^?\s]{1,2000})""",
    """URL:\s{0,100}.*?({uri_query}\?[^\s"]{1,2000})""",
    """IngressInterface: ({src_interface}[^\s,]{1,2000}?),""", 
    """EgressInterface: ({dest_interface}[^\s,]{1,2000}?),""",
    """Priority: ({priority}\d{1,100}),""",
    """AccessControlRuleName: ({rule}[^,]{1,2000}),""",
    """ApplicationProtocol: ({app_protocol}[^,]{1,2000}),""",
    """IntrusionPolicy: ({alert_name}[^,]{1,2000}),"""
  ]


}
```