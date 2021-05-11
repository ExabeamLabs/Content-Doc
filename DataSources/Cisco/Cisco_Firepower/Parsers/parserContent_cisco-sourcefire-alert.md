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
    """({host}[\w\-.]+) SFIMS:\s{0,100}Correlation Event:\s{0,100}({policy}.+?) (correlation policy|on Discovered host|on Security Intelligence) at ({time}\w+ \w+ \d\d \d\d:\d\d:\d\d \d\d\d\d \w+?)\s{0,100}(Connection Type|:)""",
    """Connection Type:\s{0,100}({alert_type}.+?) (0.0.0.0|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))\:({src_port}\d{1,100}) \((unknown|({src_country}[^\)]+))\) -> (0.0.0.0|({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))\:({dest_port}\d{1,100}) \((unknown|({dest_country}[^\)]+))\) \(({protocol}[^\)]+)\)""",
    """<\*-\s{0,100}({alert_type}[^>]*?From\s{1,100}"({src_host}[\w\-.]+)")""",
    """IP Address:\s{0,100}({src_ip}[A-Fa-f:\d.]+)""",
    """FireSIGHT SI Category: ({category}\w+)"""
  ]
  DupFields = [ "policy->alert_name" ]
}
```