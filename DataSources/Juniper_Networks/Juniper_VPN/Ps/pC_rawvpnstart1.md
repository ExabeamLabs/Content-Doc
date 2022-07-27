#### Parser Content
```Java
{
Name = raw-vpn-start-1
  Vendor = Juniper Networks
  Product = Juniper VPN
  Lms = Direct
  DataType = "vpn-start"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ Login succeeded for """, """PulseSecure: """ ]
  Fields = [
    """PulseSecure:[\s\-]{0,100}({time}\d\d\d\d\-\d\d\-\d\d\s{0,100}\d\d:\d\d:\d\d)\s{1,100}\-\s{1,100}({host}[\w\-.]{1,2000})\s{0,100}""",
    """({event_name}Login succeeded) for ({user}[^\/]{1,2000})\/({realm}[^\s]{1,2000}) from ({src_ip}[A-Fa-f\d:\.]{1,2000})""",
    """PulseSecure:[^\[]{1,2000}\[({src_ip}[a-fA-F:\d.]{1,2000})\]\s{1,100}(({domain}[^\\]{1,2000})\\)?(?:({user_email}[^@\s]{1,2000}@[^@\(]{1,2000})|({user}[^\s\\]{1,2000}))\(({realm}[^\)]{1,2000})?""",
  ]
  DupFields = [ "host->dest_host" , "user->account"]


}
```