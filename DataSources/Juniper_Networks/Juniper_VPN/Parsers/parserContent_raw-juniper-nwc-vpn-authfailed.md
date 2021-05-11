#### Parser Content
```Java
{
Name = raw-juniper-nwc-vpn-authfailed
  Vendor = Juniper Networks
  Product = Juniper VPN
  Lms = Direct
  DataType = "authentication-failed"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [  " PulseSecure:", """ authentication failed for """ ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)\s-\s""",
    """\stime="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=(.+?@\s{0,100})?(::ffff:)?({host}[^\s]+)""",
    """\sfw=(::ffff:)?({host}[\w\-\.]+)""",
    """\s(::ffff:)?(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[\w\-\.]+))\s{1,100}(Juniper|PulseSecure):""",
    """\- \[(::ffff:)?({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]\s{1,100}(({domain}[^\\]+)\\)?(?:({user_email}[^@]+@[^@(]+)|({user}[^\(]+))\(({realm}[^\)]+)?\)""",
    """({failure_reason}(Primary|Secondary) authentication failed) for\s{1,100}(({domain}[^\\]+)\\+)?(?:({user_email}[^@\s\/]+@[^@\s\/\\]+)|({user}[^\s\\\/]+))(\/({realm}.+?))\s{1,100}from(::ffff:)?({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """PulseSecure:.+?({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)\s{1,100}\-\s{1,100}({host}[\w\-.]+)""",
    """({host}[\w\-\.]+)\s{1,100}(Juniper|PulseSecure):""",
    """PulseSecure:.*?\[(::ffff:)?({src_ip}[a-fA-F:\d.]+)\]\s{1,100}(({domain}[^\\]+)\\)?(?:({user_email}[^@\s]+@[^@\s]+)|({user}[^\s]+))\(({realm}[^\)]+)?"""
  ]
  DupFields = [ "host->dest_host" ]
}
```