#### Parser Content
```Java
{
Name = snort-network-alert
  Vendor = Snort
  Product = Snort
  Lms = Direct
  DataType = "network-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"program":"snort"""", """"logT":"IDS-Snort"""", """[Classification:""" ]
  Fields = [ 
    """"@timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """"host":"({host}[^"]+)""",
    """"message":"\[({additional_info}[^"\]]+)\] ({alert_name}.+?)\s{0,100}\[Classification:\s{0,100}({alert_type}[^\]]+)\] \[Priority:\s{0,100}({alert_severity}[^\]]+)\] \{({protocol}[^\}]+)\} ({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):({src_port}\d{1,100}) -> ({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):({dest_port}\d{1,100})""",
  ]
}
```