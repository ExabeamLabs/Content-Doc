#### Parser Content
```Java
{
Name = s-juniper-vpn-timeout
  Vendor = Juniper Networks
  Product = Juniper VPN
  Lms = Splunk
  DataType = "vpn-end"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """Session timed out for""", """ (session:""", """id=firewall""" ]
  Fields = [
    """time="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)".*vpn=({host}[^\s]+).*user=(({user_email}[^@\s\/]+@[^@\s\/]+)|({user}[^\/\s]+)).*realm="({realm}[^"]+)?".*roles="({role}[^"]+)?".*src=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*"""
  ]
  DupFields = [ "host->dest_host" ]
}
```