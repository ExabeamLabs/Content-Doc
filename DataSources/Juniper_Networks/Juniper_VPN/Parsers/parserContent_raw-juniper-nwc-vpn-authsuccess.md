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
    """exabeam_host=(.+?@\s{0,100})?({host}[^\s]+)""",
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)\s-\s""",
    """\stime="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\sfw=(::ffff:)?({host}[\w\-\.]+)""",
    """\s({host}[\w\-.]+)\s{1,100}\S+\s{1,100}PulseSecure:""",
    """PulseSecure:\s{0,100}({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)\s{1,100}\-\s{1,100}(::ffff:)?({host}(?!ive)[\w\-.]+)""",
    """PulseSecure:.+?({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)\s{1,100}\-\s{1,100}(::ffff:)?({host}[\w\-.]+)""",
    """(::ffff:)?({host}[\w\-\.]+)\s{1,100}(Juniper|PulseSecure):""",
    """(::ffff:)?(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[\w\-\.]+))\s{1,100}(Juniper|PulseSecure):""",
    """\- \[(::ffff:)?({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]\s{1,100}(({domain}[^\\]+)\\)?(?:({user_email}[^@]+@[^@(]+)|({user}[^\(]+))\(({realm}[^\)]+)?\)""",
    """authentication successful for\s{1,100}(({domain}[^\\]+)\\)?(?:({user_email}[^@\s\/]+@[^@\s\/]+)|({user}[^\/]+))(\/({realm}.+?))\s{1,100}from (::ffff:)?({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """PulseSecure:.*?\[(::ffff:)?({src_ip}[a-fA-F:\d.]+)\]\s{1,100}(({domain}[^\\]+)\\)?(?:({user_email}[^@\s]+@[^@\s]+)|({user}[^\s]+))\(({realm}[^\)]+)?""",
    """user=(({user_email}[^@\s\/]+@[^@\s\/]+)|({user}[^\/\s]+))"""
  ]
  DupFields = [ "host->dest_host" ]
}
```