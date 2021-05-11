#### Parser Content
```Java
{
Name = raw-vpn-start
  Vendor = Juniper Networks
  Product = Juniper VPN
  Lms = Direct
  DataType = "vpn-start"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ Login succeeded for """, """ (session:""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d) \- .*?Login succeeded for""",
    """PulseSecure:\s{0,100}({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)\s{1,100}\-\s{1,100}({host}[\w\-.]+)""",
    """exabeam_source=(::ffff:)?({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """exabeam_host=(.+?@\s{0,100})?(::ffff:)?({host}[^\s]+)""",
    """exabeam_host=(.+?@\s{0,100})?(::ffff:)?({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """(::ffff:)?({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[\w\-\.]+)\s{0,100}(Juniper|PulseSecure):""",
    """PulseSecure:.*?\[(::ffff:)?({src_ip}[a-fA-F:\d.]+)\]\s{1,100}(({domain}[^\\]+)\\)?(?:({user_email}[^@\s]+@[^@\(]+)|({user}[^\s]+))\(({realm}[^\)]+)?""",
    """Login succeeded for (?:({user_email}[^@\s]+@[^@\s\/]+)|({user}[^\s\/]+))""",
    """Login succeeded for [^/]+/({realm}.+?)\s{1,100}\(session:""",
    """Login succeeded for .+?from (::ffff:)?({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """PulseSecure:.*?\[(::ffff:)?({src_ip}[a-fA-F:\d.]+)\]\s{1,100}(({domain}[^\\]+)\\)?(?:({user_email}[^@\s]+@[^@\(]+)|({user}[^\s\\]+))\(({realm}[^\)]+)?""",
  ]
  DupFields = [ "host->dest_host" , "user->account"]
}
```