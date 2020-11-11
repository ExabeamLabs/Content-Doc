#### Parser Content
```Java
{
Name = s-skysea-web-activity-1
  Vendor = SkySea
  Product = ClientView
  Lms = Splunk
  DataType = "web-activity"
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [""",Web????????????,""", """,Web????????????,"""]
  Fields = [
    """({host}[^,]+),(({src_ip}[A-Fa-f:\d.]+)|({src_host}[\w\-.]+)),[^,]*,({user}[^,]*),[^,]*,[^,]*,[^,]*,[^,]*,Web????????????""",
    """({time}\d\d\d\d\/\d\d\/\d\d \d\d:\d\d:\d\d)""",
    """,Web????????????,[^,]*,[^,]*,({full_url}(({protocol}[^:\\\/\s,"]+):[\\\/]+)?({web_domain}[^\\\/\s:,"]+)?(:({dest_port}\d+))?({uri_path}\/[^,]*)?)""",
    """Web????????????,([^,]*,){23}({uri_query}[^,]*),""",
    """({method}Web????????????)""",
  ]
  DupFields = ["web_domain->top_domain", "method->action"]
}
```