#### Parser Content
```Java
{
Name = juniper-web-activity-3
  Vendor = Juniper VPN
  Product = Juniper VPN
  Lms = ArcSight
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ PulseSecure:""" , """WebRequest completed,""" ]
  Fields = [
    """PulseSecure:.+?({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)\s+\-\s+({host}[\w\-.]+)""",
    """PulseSecure:.*?\[({src_ip}[a-fA-F:\d.]+)\]\s+(({domain}[^\\]+)\\)?(?:({user_email}[^@\s]+@[^@\s]+)|({user}[^\s]+))\(({realm}[^\)]+)?""",
    """WebRequest completed,\s*({method}[^\s]+)\s+\S+\s+({full_url}(({protocol}[\w]+):\/+)?({web_domain}[^\s:\\\/]+)(:({dest_port}\d+)\/+)?({uri_path}\/[^\s\?]+)?({uri_query}\?[^\s]+)?)\s+""",    
    """\Wresult=({result_code}\d+)""",
    """\Wsent=({bytes_out}\d+)""",
    """\Wreceived=({bytes_in}\d+)""",
    """from\s({src_ip}[A-Fa-f\d:.]+)""",     
  ]

}
```