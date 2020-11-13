#### Parser Content
```Java
{
Name = s-skysea-web-activity-1
  Vendor = SkySea
  Product = ClientView
  Lms = Splunk
  DataType = "web-activity"
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [""",Webアクセス,""", """,Web書き込み,"""]
  Fields = [
    """({host}[^,]+),(({src_ip}[A-Fa-f:\d.]+)|({src_host}[\w\-.]+)),[^,]*,({user}[^,]*),[^,]*,[^,]*,[^,]*,[^,]*,Webアクセス""",
    """({time}\d\d\d\d\/\d\d\/\d\d \d\d:\d\d:\d\d)""",
    """,Webアクセス,[^,]*,[^,]*,({full_url}(({protocol}[^:\\\/\s,"]+):[\\\/]+)?({web_domain}[^\\\/\s:,"]+)?(:({dest_port}\d+))?({uri_path}\/[^,]*)?)""",
    """Web書き込み,([^,]*,){23}({uri_query}[^,]*),""",
    """({method}Web書き込み)""",
  ]
  DupFields = ["web_domain->top_domain", "method->action"]
}
```