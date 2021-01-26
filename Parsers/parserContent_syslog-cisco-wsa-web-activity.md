#### Parser Content
```Java
{
Name = syslog-cisco-wsa-web-activity
  Vendor = Cisco
  Product = Cisco Secure Web Appliance
  Lms = Direct
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "epoch_sec"
  Conditions = [ """accesslog_syslog:""" ]
  Fields = [
    """exabeam_host=({host}[^\s]+)""",
    """accesslog_syslog:\s\S+\s({time}\d{10})\.\d{3}\s\S+\s({src_ip}[\d.:a-fA-F]+)\s((-|(?i)NONE|({proxy_action}[^\s\/]+?))(\/(-|({result_code}\d+)))?)\s\d+\s(-|({method}[^\s]+))""",
    """accesslog_syslog:(\s\S+){7}\s(-|({full_url}(({protocol}[^:]+):\/+)?[^\s:\/]+(:({dest_port}\d+))?\/(?:-|({uri_path}[^?\s]+))?({uri_query}\?[^\s]+)?))""",
    """accesslog_syslog:(\s\S+){8}\s"*(-|(({domain}[^\\]+)\\+)?({user}[^@"\s]+))""",
    """accesslog_syslog:(\s\S+){7}\s(\w+:\/+)?({web_domain}(?:({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|[^\s\/:]+))""",
    """accesslog_syslog:(\s\S+){11}\s(-|({action}[^\s-]+))""",
    """accesslog_syslog:(\s\S+){10}\s(["-]+|({mime}[^\s]+))""",
    """\Wdst\s*({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\WdstPort\s*({dest_port}\d+)""",
    """accesslog_syslog:(\s\S+){12}\s<(["-]+|nc|({category}[^,>]+?))\s*[,>]""",
    """\Wuserag\s*"*(?:[\s-]|({user_agent}[^"]+))""",
    """\Wuserag\s*"*(?:[\s-]|({browser}[^"]+))""",
    """\Wuserag\s*"*(?:[\s-]|({browser}[\w\-]+)\/[\d\._]+)""",
    """\Wuserag\s*"*(?:[\s-]|({browser}[^\/;]+).+({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin))""",
    """Mozilla\/.+\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
    """accesslog_syslog:(\s\S+){7}\s(?:\w+:\/+)(-|[^"]+?({top_domain}[^\/\.\s]+(?i)(\.(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+))(:|\/)""",
  ]
}
```