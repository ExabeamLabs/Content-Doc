#### Parser Content
```Java
{
Name = pulsesecure-vpn-login
  Vendor = Juniper Networks
  Product = Juniper Networks Pulse Secure
  Lms = Direct
  DataType = "vpn-start"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """PulseSecure:""", """Remote address for user""" ]
  Fields = [
    """PulseSecure: ({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d) - ({host}\S+) - \[({src_ip}[A-Fa-f:\d.]+)\] (({domain}[^\\]+)\\)?({user}[^\\\/\s\(]+)""",
    """changed from ({src_ip}[A-Fa-f:\d.]+) to ({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
  ]
  DupFields = ["user->account"]
}
```