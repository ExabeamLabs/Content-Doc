#### Parser Content
```Java
{
Name = cisco-sourcefire-alert
  Vendor = Cisco
  Product = Cisco Firepower
  Lms = Direct
  DataType = "alert"
  TimeFormat = "EEE MMM dd HH:mm:ss yyyy z"
  Conditions = [ """SFIMS: Correlation Event:""" ]
  Fields = [
    """({host}[\w\-.]+) SFIMS:\s*Correlation Event:\s*({policy}.+?) (correlation policy|on Discovered host|on Security Intelligence) at ({time}\w+ \w+ \d\d \d\d:\d\d:\d\d \d\d\d\d \w+?)\s*(Connection Type|:)""",
    """Connection Type:\s*({alert_type}.+?) (0.0.0.0|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))\:({src_port}\d+) \((unknown|({src_country}[^\)]+))\) -> (0.0.0.0|({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))\:({dest_port}\d+) \((unknown|({dest_country}[^\)]+))\) \(({protocol}[^\)]+)\)""",
    """<\*-\s*({alert_type}[^>]*?From\s+"({src_host}[\w\-.]+)")""",
    """IP Address:\s*({src_ip}[A-Fa-f:\d.]+)""",
  ]
  DupFields = [ "policy->alert_name" ]
}
```