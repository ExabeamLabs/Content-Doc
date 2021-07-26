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
    """PulseSecure:\s{0,100}({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)\s{1,100}\-\s{1,100}({host}[\w\-.]{1,2000})""",
    """exabeam_source=(::ffff:)?({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """exabeam_host=(.+?@\s{0,100})?(::ffff:)?({host}[^\s]{1,2000})""",
    """exabeam_host=(.+?@\s{0,100})?(::ffff:)?({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """(::ffff:)?({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[\w\-\.]{1,2000})\s{0,100}(Juniper|PulseSecure):""",
    """PulseSecure:.*?\[(::ffff:)?({src_ip}[a-fA-F:\d.]{1,2000})\]\s{1,100}(({domain}[^\\]{1,2000})\\)?(?:({user_email}[^@\s]{1,2000}@[^@\(]{1,2000})|({user}[^\s]{1,2000}))\(({realm}[^\)]{1,2000})?""",
    """Login succeeded for (?:({user_email}[^@\s]{1,2000}@[^@\s\/]{1,2000})|({user}[^\s\/]{1,2000}))""",
    """Login succeeded for [^/]{1,2000}/({realm}.+?)\s{1,100}\(session:""",
    """Login succeeded for .+?from (::ffff:)?({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """PulseSecure:.*?\[(::ffff:)?({src_ip}[a-fA-F:\d.]{1,2000})\]\s{1,100}(({domain}[^\\]{1,2000})\\)?(?:({user_email}[^@\s]{1,2000}@[^@\(]{1,2000})|({user}[^\s\\]{1,2000}))\(({realm}[^\)]{1,2000})?""",
  ]
  DupFields = [ "host->dest_host" , "user->account"]
}
```