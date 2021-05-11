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
    """_time"\s{0,100}:\s{0,100}"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """({alert_type}SYSTEM_POLICY_VIOLATION)""",
    """title"\s{0,100}:\s{0,100}"({alert_name}[^"]+)""",
    """"actionType"\s{0,100}:\s{0,100}"({alert_severity}ALERT_[^"]+)""",
    """hostname"\s{0,100}:\s{0,100}"({host}[^"]+)""",
    """relatedDevices[^\]]+"riskLevel"\s{0,100}:\s{0,100}({device_severity}\d{1,100})[^\]]+?\]""",
    """relatedDevices[^\]]+"name"\s{0,100}:\s{0,100}"(({src_ip}[\d:]+:[^"]+)|({src_host}[^"]+))"[^\}][^\]]"""
    """user"\s{0,100}:\s{0,100}"({user}[^"]+)""",
    """relatedDevices[^\]]+"sensor"\s{0,100}:\s{0,100}"({sensor}[^"]+)"[^"]]+?\]""",
    """relatedDevices[^\]]+"ip"\s{0,100}:\s{0,100}"({src_ip}[^"]+)"[^]]+?\]""",
    """"{1,20}relatedDevices"{1,20}:[^\]]+?("{1,20}(site|sensor)"{1,20}: \{[^}]*?"{1,20}type"{1,20}: )?.+?"{1,20}name"{1,20}: "{1,20}({device_name}[^"]+)"[^\}]"""
    """"relatedDevices[^\]]+"category"{1,20}:\s{0,100}"{1,20}({device_category}[^"]+)"[^]]+?\]"""
    """"relatedDevices[^\]]+"identifier"{1,20}:\s{0,100}"{1,20}({device_id}[^"]+)"[^]]+?\]"""
    """"relatedDevices[^\]]+"model"{1,20}:\s{0,100}"{1,20}({device_model}[^"]+)"[^]]+?\]"""
    """"{1,20}relatedDevices"{1,20}:.+?("{1,20}(site|sensor)"{1,20}: \{[^}]*?"{1,20}type"{1,20}: )?.+?"{1,20}type"{1,20}: "{1,20}(?!ACCESS_POINT_INTERFACE)({device_type}[A-Z_]+)"[^\}]"""
  ]
}
```