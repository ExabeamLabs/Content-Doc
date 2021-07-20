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
    """time="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)".*vpn=({host}[^\s]{1,2000}).*user=(({user_email}[^@\s\/]{1,2000}@[^@\s\/]{1,2000})|({user}[^\/\s]{1,2000})).*realm="({realm}[^"]{1,2000})?".*roles="({role}[^"]{1,2000})?".*changed from ({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) to ({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""
  ]
}
```