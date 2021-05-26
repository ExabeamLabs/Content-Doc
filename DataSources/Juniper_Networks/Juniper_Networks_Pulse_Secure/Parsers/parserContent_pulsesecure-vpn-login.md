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
    """PulseSecure: (\S+\s\S+\s\S+\s)?({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d) - (::ffff:)?({host}\S+) - \[(::ffff:)?({src_ip}[A-Fa-f:\d.]{1,2000})\] (({domain}[^\\]{1,2000})\\)?({user}[^\\\/\s\(]{1,2000})""",
    """changed from (::ffff:)?({src_ip}[A-Fa-f:\d.]{1,2000}) to (::ffff:)?({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
  ]
  DupFields = ["user->account"]
}
```