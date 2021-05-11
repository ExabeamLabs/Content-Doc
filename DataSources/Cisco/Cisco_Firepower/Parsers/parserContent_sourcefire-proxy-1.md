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
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """\w+\s{1,100}\d{1,100} \d\d:\d\d:\d\d ({host}[\w.\-]+)""",
    """({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}Z)\s{1,100}({host}[\w\-.]+)?\s{0,100}(\(|\%)""",
    """({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d)""",
    """SrcIP:\s{0,100}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """DstIP:\s{0,100}({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """DstIP:\s{0,100}({web_domain}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """SrcPort:\s{0,100}({src_port}\d{1,100})""",
    """DstPort:\s{0,100}({dest_port}\d{1,100})""",
    """AccessControlRuleAction:\s{0,100}({action}[^,]+)""",
    """User:\s{0,100}(Unknown|No Authentication Required|({user}[^,\s]+))""",
    """Client:\s{0,100}({user_agent}[^,]+)""",
    """UserAgent:\s{0,100}({user_agent}.+?),\s{0,100}Client:""",
    """UserAgent:\s{0,100}({browser}\w\-.)""",
    """UserAgent:\s{0,100}(?:-|({browser}[^\/\s,]+).+({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin))""",
    """UserAgent:\s{0,100}(?:-|Mozilla\/.+\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident))""",
    """UserAgent:\s{0,100}(?:-|Mozilla\/.+\((?:BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+Gecko\/\d{1,100}\s{1,100}({browser}\w+))""",
    """Protocol:\s{0,100}({protocol}[^,]+)""",
    """InitiatorBytes:\s{0,100}({bytes_out}[^,]+)""",
    """ResponderBytes:\s{0,100}({bytes_in}[^,]+)""",
    """URLCategory:\s{0,100}({categories}({category}[^,;]+)[^,]*)""",
    """URL:\s{0,100}({full_url}\S+?)(,\s{0,100}\w+:|\s)""",
    """URL:\s{0,100}(?:-|\w+:\/+)({web_domain}[^\s\/:]+)""",
    """URL:\s{0,100}(?:-|\w+:\/+[^\/]+)({uri_path}\/[^?\s]+)""",
    """URL:\s{0,100}.*?({uri_query}\?[^\s"]+)""",
    """URL:(.*?)({top_domain}(?!(?:\d{1,100}\.){3}\d{1,100})[^\.\s\/:]+(?=(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|ms|fm|news|tech|pn|impserver|work|so|pw))+(,|\/|\s|:))[^,\/\s]+)"""
    """IngressInterface: ({src_interface}[^\s,]+?),""", 
    """EgressInterface: ({dest_interface}[^\s,]+?),""",
    """Priority: ({priority}\d{1,100}),""",
    """AccessControlRuleName: ({rule}[^,]+),""",
    """ApplicationProtocol: ({app_protocol}[^,]+),""",
    """IntrusionPolicy: ({alert_name}[^,]+),"""
  ]
}
```