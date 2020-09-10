#### Parser Content
```Java
{
Name = syslog-cisco-wsa-web-activity
  Vendor = Cisco
  Product = Cisco Web Security Appliance
  Lms = Direct
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "epoch_sec"
  Conditions = [ """accesslog_syslog:""" ]
  Fields = [
    """({time}\d{10})\.\d{3}""",
    """exabeam_host=([^=]+@\s*)?({host}[^\s]+)""",
    """\d{10}\.\d{3}\s+\S+\s(?:-|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))""",
    """\d{10}\.\d{3}\s+([^\s]+\s){2}(?:-|({proxy_action}.+?)(\/(?:-|({result_code}\d+)))?)\s""",
    """\d{10}\.\d{3}\s+([^\s]+\s){4}(?:-|({method}[^\s]+))""",
    """\d{10}\.\d{3}\s+([^\s]+\s){5}(?:-|({full_url}(({protocol}[^:]+):\/+)?[^\s:\/]+(:({dest_port}\d+))?\/(?:-|({uri_path}[^?\s]+))?({uri_query}\?[^\s]+)?))""",
    """\d{10}\.\d{3}\s+([^\s]+\s){6}"*(?:-|(({domain}[^\\]+)\\+)?({user}[^@"\s]+))""",
    """\d{10}\.\d{3}\s+([^\s]+\s){5}(\w+:\/+)?({web_domain}(?:({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|[^\s\/:]+))""",
    """\d{10}\.\d{3}\s+([^\s]+\s){9}(?:-|({action}[^\s-]+))""",
    """\d{10}\.\d{3}\s+([^\s]+\s){8}(?:["-]+|({mime}[^\s]+))""",
    """\Wdst\s*({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\WdstPort\s*({dest_port}\d+)""",
    """\d{10}\.\d{3}\s+([^\s]+\s){9}[^\s]+\s+<(?:-|nc|({category}[^,>]+))""",
    """\Wuserag\s*"*(?:[\s-]|({user_agent}[^"]+))""",
    """\Wuserag\s*"*(?:[\s-]|({browser}[^"]+))""",
    """\Wuserag\s*"*(?:[\s-]|({browser}[\w\-]+)\/[\d\._]+)""",
    """\Wuserag\s*"*(?:[\s-]|({browser}[^\/;]+).+({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin))""",
    """Mozilla\/.+\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
    """\d{10}\.\d{3}\s+(?:[^\s]+\s){5}(\d+\/)?(?:\w+:\/+)(?:-|.*?({top_domain}(?!(?:\d+\.){3}\d+)[^\.\s\/:]+(?=(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+(,|\/|\s))[^,\/\s]+))""" 
  ]
}
```