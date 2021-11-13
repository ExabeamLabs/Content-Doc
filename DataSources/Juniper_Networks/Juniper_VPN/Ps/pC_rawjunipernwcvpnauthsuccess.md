#### Parser Content
```Java
{
Name = raw-juniper-nwc-vpn-authsuccess
  Vendor = Juniper Networks
  Product = Juniper VPN
  Lms = Direct
  DataType = "authentication-successful"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [  " PulseSecure:", """ authentication successful for """ ]
  Fields = [
    """exabeam_host=(.+?@\s{0,100})?({host}[^\s]{1,2000})""",
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)\s-\s""",
    """\stime="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\sfw=(::ffff:)?({host}[\w\-\.]{1,2000})""",
    """\s({host}[\w\-.]{1,2000})\s{1,100}\S+\s{1,100}PulseSecure:""",
    """PulseSecure:\s{0,100}({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)\s{1,100}\-\s{1,100}(::ffff:)?({host}(?!ive)[\w\-.]{1,2000})""",
    """PulseSecure:.+?({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)\s{1,100}\-\s{1,100}(::ffff:)?({host}[\w\-.]{1,2000})""",
    """(::ffff:)?({host}[\w\-\.]{1,2000})\s{1,100}(Juniper|PulseSecure):""",
    """(::ffff:)?(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[\w\-\.]{1,2000}))\s{1,100}(Juniper|PulseSecure):""",
    """\- \[(::ffff:)?({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]\s{1,100}(({domain}[^\\]{1,2000})\\)?(?:({user_email}[^@]{1,2000}@[^@(]{1,2000})|({user}[^\(]{1,2000}))\(({realm}[^\)]{1,2000})?\)""",
    """authentication successful for\s{1,100}(({domain}[^\\]{1,2000})\\)?(?:({user_email}[^@\s\/]{1,2000}@[^@\s\/]{1,2000})|({user}[^\/]{1,2000}))(\/({realm}.+?))\s{1,100}from (::ffff:)?({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """PulseSecure:.*?\[(::ffff:)?({src_ip}[a-fA-F:\d.]{1,2000})\]\s{1,100}(({domain}[^\\]{1,2000})\\)?(?:({user_email}[^@\s]{1,2000}@[^@\s]{1,2000})|({user}[^\s]{1,2000}))\(({realm}[^\)]{1,2000})?""",
    """user=(({user_email}[^@\s\/]{1,2000}@[^@\s\/]{1,2000})|({user}[^\/\s]{1,2000}))"""
  ]
  DupFields = [ "host->dest_host" ]


}
```