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
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """\w+\s+\d+ \d\d:\d\d:\d\d ({host}[\w.\-]+)""",
    """({time}\d+-\d+-\d+T\d+:\d+:\d+Z)\s+({host}[\w\-.]+)?\s*(\(|\%)""",
    """SrcIP:\s*({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """DstIP:\s*({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """DstIP:\s*({web_domain}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """SrcPort:\s*({src_port}\d+)""",
    """DstPort:\s*({dest_port}\d+)""",
    """AccessControlRuleAction:\s*({action}[^,]+)""",
    """User:\s*(Unknown|No Authentication Required|({user}[^,\s]+))""",
    """Client:\s*({user_agent}[^,]+)""",
    """UserAgent:\s*({user_agent}.+?),\s*Client:""",
    """UserAgent:\s*({browser}\w\-.)""",
    """UserAgent:\s*(?:-|({browser}[^\/\s,]+).+({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin))""",
    """UserAgent:(?:-|Mozilla\/.+\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident))""",
    """UserAgent:(?:-|Mozilla\/.+\((?:BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+Gecko\/\d+\s+({browser}\w+))""",
    """Protocol:\s*({protocol}[^,]+)""",
    """InitiatorBytes:\s*({bytes_out}[^,]+)""",
    """ResponderBytes:\s*({bytes_in}[^,]+)""",
    """URLCategory:\s*({categories}({category}[^,;]+)[^,]*)""",
    """URL:\s*({full_url}\S+?)(,\s*\w+:|\s)""",
    """URL:\s*(?:-|\w+:\/+)({web_domain}[^\s\/:]+)""",
    """URL:\s*(?:-|\w+:\/+[^\/]+)({uri_path}\/[^?\s]+)""",
    """URL:\s*.*?({uri_query}\?[^\s"]+)""",
    """URL:(.*?)({top_domain}(?!(?:\d+\.){3}\d+)[^\.\s\/:]+(?=(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|ms|fm|news|tech|pn|impserver|work|so|pw))+(,|\/|\s|:))[^,\/\s]+)"""
    """IngressInterface: ({src_interface}[^\s,]+?),""", 
    """EgressInterface: ({dest_interface}[^\s,]+?),""",
  ]
}
```