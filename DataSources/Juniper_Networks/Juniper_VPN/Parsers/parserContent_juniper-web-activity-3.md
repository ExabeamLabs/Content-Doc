#### Parser Content
```Java
{
Name = juniper-web-activity-3
  Vendor = Juniper Networks
  Product = Juniper VPN
  Lms = ArcSight
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ PulseSecure:""" , """WebRequest completed,""" ]
  Fields = [
    """PulseSecure:.+?({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)\s{1,100}\-\s{1,100}(::ffff:)?({host}[\w\-.]+)""",
    """PulseSecure:.*?\[({src_ip}[a-fA-F:\d.]+)\]\s{1,100}(({domain}[^\\]+)\\)?(?:({user_email}[^@\s]+@[^@\s]+)|({user}[^\s]+))\(({realm}[^\)]+)?""",
    """WebRequest completed,\s{0,100}({method}[^\s]+)\s{1,100}\S+\s{1,100}({full_url}(({protocol}[\w]+):\/+)?({web_domain}[^\s:\\\/]+)(:({dest_port}\d{1,100})\/+)?({uri_path}\/[^\s\?]+)?({uri_query}\?[^\s]+)?)\s{1,100}""",    
    """\Wresult=({result_code}\d{1,100})""",
    """\Wsent=({bytes_out}\d{1,100})""",
    """\Wreceived=({bytes_in}\d{1,100})""",
    """from\s(::ffff:)?({src_ip}[A-Fa-f\d:.]+)""",     
  ]

}
```