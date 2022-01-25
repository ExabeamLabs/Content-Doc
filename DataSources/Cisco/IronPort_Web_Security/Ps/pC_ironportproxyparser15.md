#### Parser Content
```Java
{
Name = ironport-proxy-parser-15
  Vendor = Cisco
  Product = IronPort Web Security
  Lms = Syslog
  DataType = "web-activity"
  TimeFormat = "epoch"
  Conditions = [ """W3C_Logs_Syslog_Exabeam:""", """Info:""" ]
  Fields = [
    """({host}[^\s]{1,2000})\sW3C_Logs_Syslog_Exabeam: Info: ({time}\d{1,12}\.\d{1,3})\s\S{1,2000}\s({src_ip}[a-fA-F\d:.]{1,2000})\s(-|"([^\\"]{1,2000}\\)?({user}[^"@]{1,2000})(@({domain}[^"]{1,2000}))?")\s({src_port}\d{1,100})\s(-|({dest_ip}[a-fA-F\d:.]{1,2000}))\s({dest_port}\d{1,100})\s({full_url}(\w{1,2000}:\/{1,20})?({web_domain}[^\/:]{1,2000})(:\d{1,100})?({uri_path}\/[^\s?]{0,2000})?({uri_query}\?[^\s]{0,2000})?)\s(\S{1,2000}\s){3}(-|"({user_agent}[^"]{1,2000})")\s\S{1,2000}\s({method}[^\s]{1,2000})\s({result_code}\d{1,100})\s(\S{1,2000}\s){2}(NONE|({proxy_action}[^\s]{1,2000}))"""
  ]


}
```