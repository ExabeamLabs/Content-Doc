#### Parser Content
```Java
{
Name = s-juniper-vpn-realm
  Vendor = Juniper Networks
  Product = Juniper VPN
  Lms = Splunk
  DataType = "vpn-start"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ " PulseSecure:", " realm restrictions successfully passed", "id=firewall" ]
  Fields = [
    """time="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)".*vpn=({host}[^\s]{1,2000}).*user=(({user_email}[^@\s\/]{1,2000}@[^@\s\/]{1,2000})|({user}[^\/\s]{1,2000})).*realm="({realm}[^"]{1,2000})?".*roles="({role}[^"]{1,2000})?".*src=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*""",
  ]
  DupFields = [ "host->dest_host" ]
}
```