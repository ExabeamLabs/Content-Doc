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
    """PulseSecure:.+?({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)\s{1,100}\-\s{1,100}(::ffff:)?({host}[\w\-.]{1,2000})""",
    """PulseSecure:.*?\[({src_ip}[a-fA-F:\d.]{1,2000})\]\s{1,100}(({domain}[^\\]{1,2000})\\)?(?:({user_email}[^@\s]{1,2000}@[^@\s]{1,2000})|({user}[^\s]{1,2000}))\(({realm}[^\)]{1,2000})?""",
    """WebRequest completed,\s{0,100}({method}[^\s]{1,2000})\s{1,100}\S+\s{1,100}({full_url}(({protocol}[\w]{1,2000}):\/+)?({web_domain}[^\s:\\\/]{1,2000})(:({dest_port}\d{1,100})\/+)?({uri_path}\/[^\s\?]{1,2000})?({uri_query}\?[^\s]{1,2000})?)\s{1,100}""",    
    """\Wresult=({result_code}\d{1,100})""",
    """\Wsent=({bytes_out}\d{1,100})""",
    """\Wreceived=({bytes_in}\d{1,100})""",
    """from\s(::ffff:)?({src_ip}[A-Fa-f\d:.]{1,2000})""",     
  ]

}
```