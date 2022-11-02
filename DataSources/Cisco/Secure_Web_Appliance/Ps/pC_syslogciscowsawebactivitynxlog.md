#### Parser Content
```Java
{
Name = syslog-cisco-wsa-web-activity-nxlog
  Vendor = Cisco
  Product = Secure Web Appliance
  Lms = Direct
  DataType = "web-activity"
  TimeFormat = "epoch_sec"
  Conditions = [ """ NXLOG_SYSLOG: """ ]
  Fields = [
    """NXLOG_SYSLOG:\s\S+\s({time}\d{10})\.\d{3}\s\S+\s({src_ip}[\d.:a-fA-F]{1,2000})\s((-|(?i)NONE|({proxy_action}[^\s\/]{1,2000}?))(\/(-|({result_code}\d{1,100})))?)\s\d{1,100}\s(-|({method}[^\s]{1,2000}))""",
    """NXLOG_SYSLOG:(\s\S+){7}\s(-|({full_url}(({protocol}[^:]{1,2000}):\/+)?[^\s:\/]{1,2000}(:({dest_port}\d{1,100}))?\/(?:-|({uri_path}[^?\s]{1,2000}))?({uri_query}\?[^\s]{1,2000})?))""",
    """NXLOG_SYSLOG:(\s\S+){8}\s"{0,20}(-|(({domain}[^\\]{1,2000})\\+)?({user}[^@"\s]{1,2000}))""",
    """NXLOG_SYSLOG:(\s\S+){7}\s(\w+:\/+)?(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({web_domain}[^\s\/:]{1,2000}))""",
    """NXLOG_SYSLOG:(\s\S+){11}\s(-|({action}[^\s-]{1,2000}))""",
    """NXLOG_SYSLOG:(\s\S+){10}\s(["-]{1,2000}|({mime}[^\s]{1,2000}))""",
    """NXLOG_SYSLOG:(\s\S+){12}\s<["-]{1,2000}(\-|nc|({category}[^,>\-"]{1,2000}?))\s{0,100}[,>"]"""
  ]


}
```