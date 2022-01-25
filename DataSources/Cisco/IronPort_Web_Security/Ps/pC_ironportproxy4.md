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
     """Info:\s.*?\s({src_ip}\d{1,100}.\d{1,100}.\d{1,100}.\d{1,100})\s({proxy_action}[^\/\s]{1,2000})\/({result_code}\d{1,100})\s\d{1,100}\s({method}[^\s]{1,2000})\s((({dest_ip}\d{1,100}.\d{1,100}.\d{1,100}.\d{1,100}):({dest_port}\d{1,100})\s)|({full_url}[^\s]{1,2000}))?.+?\sDIRECT\/({web_domain}[^\s]{1,2000})""",
     """User\sAgent\s=\s(-,\s|"{0,20}({user_agent}[^"=]{1,2000}))""",
     """<\d{1,100}>\w+ \d{1,100} \d{1,100}:\d{1,100}:\d{1,100}\s{1,100}({host}[^\s]{1,2000}) xb-accesslog: Info:"""
     """"(-|({category}[^"]{1,2000}?))",([^,]{1,2000}?,){19}->"""
  ]
 

}
```