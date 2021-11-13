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
    """exabeam_host=({host}[^\s]{1,2000})""",
    """accesslog_syslog:\s\S+\s({time}\d{10})\.\d{3}\s\S+\s({src_ip}[\d.:a-fA-F]{1,2000})\s((-|(?i)NONE|({proxy_action}[^\s\/]{1,2000}?))(\/(-|({result_code}\d{1,100})))?)\s\d{1,100}\s(-|({method}[^\s]{1,2000}))""",
    """accesslog_syslog:(\s\S+){7}\s(-|({full_url}(({protocol}[^:]{1,2000}):\/+)?[^\s:\/]{1,2000}(:({dest_port}\d{1,100}))?\/(?:-|({uri_path}[^?\s]{1,2000}))?({uri_query}\?[^\s]{1,2000})?))""",
    """accesslog_syslog:(\s\S+){8}\s"{0,20}(-|(({domain}[^\\]{1,2000})\\+)?({user}[^@"\s]{1,2000}))""",
    """accesslog_syslog:(\s\S+){7}\s(\w+:\/+)?({web_domain}(?:({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|[^\s\/:]{1,2000}))""",
    """accesslog_syslog:(\s\S+){11}\s(-|({action}[^\s-]{1,2000}))""",
    """accesslog_syslog:(\s\S+){10}\s(["-]{1,2000}|({mime}[^\s]{1,2000}))""",
    """\Wdst\s{0,100}({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\WdstPort\s{0,100}({dest_port}\d{1,100})""",
    """accesslog_syslog:(\s\S+){12}\s<(["-]{1,2000}|nc|({category}[^,>]{1,2000}?))\s{0,100}[,>]""",
    """\Wuserag\s{0,100}"{0,20}(?:[\s-]|({user_agent}[^"]{1,2000}))""",
  ]


}
```