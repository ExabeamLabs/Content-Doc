#### Parser Content
```Java
{
Name = elk-cisco-wsa-web-activity
  Vendor = Cisco
  Product = Cisco Secure Web Appliance
  Lms = Direct
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "epoch_sec"
  Conditions = [ """accesslog_ELK:""" ]
  Fields = [
    """({time}\d{10})\.\d{3}""",
    """exabeam_host=([^=]+@\s{0,100})?({host}[^\s]+)""",
    """\d{10}\.\d{3}\s{1,100}\S+\s(?:-|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))""",
    """\d{10}\.\d{3}\s{1,100}([^\s]+\s){2}(?:-|({proxy_action}.+?)(\/(?:-|({result_code}\d{1,100})))?)\s""",
    """\d{10}\.\d{3}\s{1,100}([^\s]+\s){4}(?:-|({method}[^\s]+))""",
    """\d{10}\.\d{3}\s{1,100}([^\s]+\s){5}(?:-|({full_url}(({protocol}[^:]+):\/+)?[^\s:\/]+(:({dest_port}\d{1,100}))?\/(?:-|({uri_path}[^?\s]+))?({uri_query}\?[^\s]+)?))""",
    """\d{10}\.\d{3}\s{1,100}([^\s]+\s){6}"{0,20}(?:-|(({domain}[^\\]+)\\+)?({user}[^@"\s]+))""",
    """\d{10}\.\d{3}\s{1,100}([^\s]+\s){5}(\w+:\/+)?({web_domain}(?:({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|[^\s\/:]+))""",
    """\d{10}\.\d{3}\s{1,100}([^\s]+\s){5}(?:-|({full_url}(({protocol}[^:]+):\/+)?[^\s:\/]+(:({dest_port}\d{1,100}))?\/(?:-|({uri_path}[^?\s]+))?({uri_query}\?[^\s]+)?))""",
    """\d{10}\.\d{3}\s{1,100}([^\s]+\s){9}(?:-|({action}[^\s-]+))""",
    """\d{10}\.\d{3}\s{1,100}([^\s]+\s){8}(?:["-]+|({mime}[^\s]+))""",
    """\Wdst\s{0,100}({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\WdstPort\s{0,100}({dest_port}\d{1,100})""",
    """\d{10}\.\d{3}\s{1,100}([^\s]+\s){9}[^\s]+\s{1,100}<(?:-|nc|({category}[^,>]+))""",
    """\Wuserag\s{0,100}"{0,20}(?:[\s-]|({user_agent}[^"]+))""",
    """\Wuserag\s{0,100}"{0,20}(?:[\s-]|({browser}[^"]+))""",
    """\Wuserag\s{0,100}"{0,20}(?:[\s-]|({browser}[\w\-]+)\/[\d\._]+)""",
    """\Wuserag\s{0,100}"{0,20}(?:[\s-]|({browser}[^\/;]+).+({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin))""",
    """Mozilla\/.+\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
    """\d{10}\.\d{3}\s{1,100}(?:[^\s]+\s){5}(\d{1,100}\/)?(?:\w+:\/+)(?:-|.*?({top_domain}(?!(?:\d{1,100}\.){3}\d{1,100})[^\.\s\/:]+(?=(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+(,|\/|\s))[^,\/\s]+))"""
  ]
}
```