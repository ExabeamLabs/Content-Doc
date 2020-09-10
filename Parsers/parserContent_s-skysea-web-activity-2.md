#### Parser Content
```Java
{
Name = s-skysea-web-activity-2
  Vendor = SkySea
  Product = ClientView
  Lms = Splunk
  DataType = "web-activity"
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [""",Webアクセス,""", """,,Webアクセス,"""]
  Fields = [
    """({host}[^,]+),(({src_ip}[A-Fa-f:\d.]+)|({src_host}[\w\-.]+)),[^,]*,({user}[^,]*),[^,]*,[^,]*,[^,]*,[^,]*,Webアクセス""",
    """({time}\d\d\d\d\/\d\d\/\d\d \d\d:\d\d:\d\d)""",
    """,Webアクセス,[^,]*,[^,]*,({full_url}(({protocol}[^:\\\/\s,"]+):[\\\/]+)?({web_domain}[^\\\/\s:,"]+)?(:({dest_port}\d+))?({uri_path}\/[^,]*)?)""",
    """({method}Webアクセス)""",
  ]
  DupFields = ["web_domain->top_domain", "method->action"]
}
```