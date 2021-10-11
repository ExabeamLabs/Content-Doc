#### Parser Content
```Java
{
Name = symantec-web-activity-2
  Vendor = Symantec
  Product = Symantec WSS
  Lms = Splunk
  DataType = "web-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """destinationServiceName=Symantec WSS""", """OBSERVED""", """http"""  ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[^\s]{1,2000})""",
    """cs6=\[([^,]{1,2000},\s){5}({src_ip}[a-fA-F\d:.]{1,2000}),\s(-|non-interactive-user|({user}[^,]{1,2000}))""",
    """\[[^]]{1,2000}?(({action}OBSERVED)),\s({categories}({category}[^,;]{1,2000})[^,]{0,2000}),\s(-|({referrer}.+?))\s{0,100},\s({result_code}\d{1,100}),\s(-|({proxy_action}[^,]{1,2000})),\s({method}[^,]{1,2000}),\s(-|({mime}[^,]{1,2000})),\s({protocol}[^,]{1,2000}),\s({web_domain}[^,]{1,2000}),\s({dest_port}\d{1,100}),\s({uri_path}[^\n]{1,4000}?)\s{0,100},\s{1,100}(-|({uri_query}\?.*?))\s{0,100},\s{1,100}(-|.+?),\s(none|-|({user_agent}[^\/,]{1,2000}\/[\d\.]{1,10}[^\n]{1,2000}?)|({=user_agent}[^,]{1,2000}))?,\s(\d{1,3}\.){3}\d{1,3},\s({bytes_out}\d{1,100}),\s({bytes_in}\d{1,100})(,\s[^,]{1,2000}){5},\sclient(,\s[^,]{1,4000}){22},\s(-|({dest_ip}[a-fA-F\d:.]{1,2000}))""",
    """\s({user_agent}Mozilla[^\n]{1,2000}?),\s(\d{1,3}\.){3}\d{1,3},\s\d{1,100},\s\d{1,100}""",
  ]
}
```