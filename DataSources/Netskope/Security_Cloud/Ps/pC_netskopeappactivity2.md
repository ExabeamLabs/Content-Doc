#### Parser Content
```Java
{
Name = netskope-app-activity-2
  Vendor = Netskope
  Product = Security Cloud
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [""""app":""", """"access_method":""", """"category":""", """"browser_session_id":""", """"src-application-name":"Netskope""""]
  Fields = [
    """"time":"({time}\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)"""",
    """"event-name":"({event_name}[^"]{1,2000})"""",
    """"src-ip":"({src_ip}[a-fA-F\d:\.]{1,2000})"""",
    """"user":"(({user_email}[^@"\s]{1,2000}@[^@"\s]{1,2000}\.[^"\s]{1,2000})|(({domain}[^"@\\\/\s]{1,2000})[\\\/]{1,2000})?({user}[^"@\\\/\s]{1,2000}))"""",
    """"app":"({app}[^"]{1,2000})""",
    """"domain":"({domain}[^"]{1,2000})"""",
    """"user-email":"({user_email}[^@"]{1,2000}@[^"\.]{1,2000}\.[^"]{1,2000})"""",
    """"dstip":"({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """"useragent":"({user_agent}[^"]{1,2000})"""",
    """"type":"({activity}[^",]{1,2000})""",
  ]


}
```