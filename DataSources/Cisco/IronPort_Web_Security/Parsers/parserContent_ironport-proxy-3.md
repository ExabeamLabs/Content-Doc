#### Parser Content
```Java
{
Name = ironport-proxy-3
   Vendor = Cisco
  Product = IronPort Web Security
   Lms = Syslog
   DataType = "web-activity"
   TimeFormat = "yyyy-dd-MM HH:mm:ss.SSS"
   Conditions = ["""xb-accesslog: Info""", "DIRECT"]
   Fields = [
     """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d\.\d\d\d)""",
      """Info:\s.*?\s({src_ip}\d+.\d+.\d+.\d+)\s({proxy_action}[^\/]+)\/({result_code}\d+)\s\d+\s({method}[^\s]+)\s(({dest_ip}\d+.\d+.\d+.\d+):({dest_port}\d+)\s)?.+?\sDIRECT\/({full_url}.+?\.({top_domain}.*\.(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))[^\s]?)""",  
     """User\sAgent\s=\s(-\s|"({user_agent}({browser}[^\(]+)\(({os}[^;]+)[^"]+))""", 
     """<\d+>\w+ \d+ \d+:\d+:\d+\s+({host}[^\s]+) xb-accesslog: Info:"""
     """"(-|({category}[^"]+?))",([^,]+?,){19}->"""
  ]
 }
```