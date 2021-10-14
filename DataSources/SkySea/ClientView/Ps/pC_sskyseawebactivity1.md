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
    """({host}[^,]{1,2000}),(({src_ip}[A-Fa-f:\d.]{1,2000})|({src_host}[\w\-.]{1,2000})),[^,]{0,2000},({user}[^,]{0,2000}),[^,]{0,2000},[^,]{0,2000},[^,]{0,2000},[^,]{0,2000},Webアクセス""",
    """({time}\d\d\d\d\/\d\d\/\d\d \d\d:\d\d:\d\d)""",
    """,Webアクセス,[^,]{0,2000},[^,]{0,2000},({full_url}(({protocol}[^:\\\/\s,"]{1,2000}):[\\\/]{1,2000})?({web_domain}[^\\\/\s:,"]{1,2000})?(:({dest_port}\d{1,100}))?({uri_path}\/[^,]{0,2000})?)""",
    """Web書き込み,([^,]{0,2000},){23}({uri_query}[^,]{0,2000}),""",
    """({method}Web書き込み)""",
  ]
  DupFields = ["method->action"]
}
```