#### Parser Content
```Java
{
Name = armis-alert-iot
  Vendor = Armis
  Product = Armis
  Lms = Splunk
  DataType = "alert-iot"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """"relatedDevices":""", """"actionType":""" , """"hostname":""", """"type": "SYSTEM_POLICY_VIOLATION""""  ]
  Fields = [
    """_time"\s*:\s*"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """({alert_type}SYSTEM_POLICY_VIOLATION)""",
    """title"\s*:\s*"({alert_name}[^"]+)""",
    """"actionType"\s*:\s*"({alert_severity}ALERT_[^"]+)""",
    """hostname"\s*:\s*"({host}[^"]+)""",
    """relatedDevices[^\]]+"riskLevel"\s*:\s*({device_severity}\d+)[^\]]+?\]""",
    """relatedDevices[^\]]+"name"\s*:\s*"(({src_ip}[\d:]+:[^"]+)|({src_host}[^"]+))"[^\}][^\]]"""
    """user"\s*:\s*"({user}[^"]+)""",
    """relatedDevices[^\]]+"sensor"\s*:\s*"({sensor}[^"]+)"[^"]]+?\]""",
    """relatedDevices[^\]]+"ip"\s*:\s*"({src_ip}[^"]+)"[^]]+?\]""",
    """"+relatedDevices"+:[^\]]+?("+(site|sensor)"+: \{[^}]*?"+type"+: )?.+?"+name"+: "+({device_name}[^"]+)"[^\}]"""
    """"relatedDevices[^\]]+"category"+:\s*"+({device_category}[^"]+)"[^]]+?\]"""
    """"relatedDevices[^\]]+"identifier"+:\s*"+({device_id}[^"]+)"[^]]+?\]"""
    """"relatedDevices[^\]]+"model"+:\s*"+({device_model}[^"]+)"[^]]+?\]"""
    """"+relatedDevices"+:.+?("+(site|sensor)"+: \{[^}]*?"+type"+: )?.+?"+type"+: "+(?!ACCESS_POINT_INTERFACE)({device_type}[A-Z_]+)"[^\}]"""
  ]
}
```