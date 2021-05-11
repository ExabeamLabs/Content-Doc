#### Parser Content
```Java
{
Name = ironport-proxy-4
   Vendor = Cisco
  Product = IronPort Web Security
   Lms = Syslog
   DataType = "web-activity"
   TimeFormat = "yyyy-dd-MM HH:mm:ss.SSS"
   Conditions = ["""xb-accesslog: Info"""    ]
   Fields = [
     """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d\.\d\d\d)""",
     """Info:\s.*?\s({src_ip}\d{1,100}.\d{1,100}.\d{1,100}.\d{1,100})\s({proxy_action}[^\/]+)\/({result_code}\d{1,100})\s\d{1,100}\s({method}[^\s]+)\s{0,100}({full_url}[^\s]+?\.({top_domain}[^:\/]+\.(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))[^\s]*)""",
     """User\sAgent\s=\s(-,\s|"{0,20}({user_agent}[^"=]+))""",
     """<\d{1,100}>\w+ \d{1,100} \d{1,100}:\d{1,100}:\d{1,100}\s{1,100}({host}[^\s]+) xb-accesslog: Info:"""
     """"(-|({category}[^"]+?))",([^,]+?,){19}->"""
  ]
 }
```