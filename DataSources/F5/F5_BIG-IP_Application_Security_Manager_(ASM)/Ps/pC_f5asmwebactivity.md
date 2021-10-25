#### Parser Content
```Java
{
Name = f5-asm-web-activity
  Vendor = F5
  Product = F5 BIG-IP Application Security Manager (ASM)
  Lms = Splunk
  DataType = "web-activity"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ """,device_vendor="F5"""", """,client_ip=""", """,client_port=""", """,http_method="""", """,configured_mitigation_action=""" ]
  Fields = [
    """,request_date_time="({time}\w{1,100}\s\d\d\s\d\d\d\d\s\d\d:\d\d:\d\d)"""",
    """hostname="({host}[\w\-.]{1,2000})"""",
    """,host="({web_domain}[^:"]{1,2000})""",
    """,client_ip="({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
    """,client_port="({src_port}\d{1,2000})"""",
    """,dest_ip="({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
    """dest_port="({dest_port}\d{1,2000})"""",
    """http_method="({method}[^"]{1,2000})"""",
    """http_protocol_indication="({protocol}[^"]{1,2000})"""",
    """configured_mitigation_action="(None|({outcome}[^"]{1,2000}))"""",
    """((?i)User-Agent):\s{0,100}({user_agent}[^"]{1,2000}?)[\\r\\n]{1,2000}([\w-]{1,2000}:|")""",
    """http_request="(\w{1,2000}\s)?({uri_path}\/[^"\s?]{1,2000}?)(\?({uri_query}[^\s]{1,2000}))?\s"""
  ]
}
```