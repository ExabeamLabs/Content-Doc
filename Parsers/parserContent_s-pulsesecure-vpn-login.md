#### Parser Content
```Java
{
Name = s-pulsesecure-vpn-login
  Vendor = Juniper Networks
  Product = Juniper Networks Pulse Secure
  Lms = Splunk
  DataType = "vpn-start"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """PulseSecure:""", """Remote address for user""", """id=firewall""" ]
  Fields = [
    """time="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)".*vpn=({host}[^\s]+).*user=(({user_email}[^@\s\/]+@[^@\s\/]+)|({user}[^\/\s]+)).*realm="({realm}[^"]+)?".*roles="({role}[^"]+)?".*changed from ({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) to ({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""
  ]
}
```