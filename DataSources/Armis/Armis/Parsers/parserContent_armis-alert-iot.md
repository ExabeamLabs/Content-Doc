#### Parser Content
```Java
{
Name = armis-alert-iot
  Vendor = Armis
  Product = Armis
  Lms = Splunk
  DataType = "alert-iot"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """device_0_type"""", """device_0_model"""" ,""""type":"System Policy Violation""""  ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)"""
    """"time":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)"""
    """({alert_type}System Policy Violation)""",
    """title"\s*:\s*"({alert_name}[^"]+)""",
    """severity":"({alert_severity}[^"]+)""",
    """status":"({alert_status}[^"]+)""",
    """"deviceIds":\[({device_id_list}[^\]]+)""",
    """"device_0_ipAddress":"({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """"device_0_id":({device_id}\d+)""",
    """"device_0_name":"({device_name}[^"]+)""",
    """"device_0_category":"({device_category}[^"]+)""",
    """"device_0_riskLevel":({device_severity}\d+)""",
    """"device_0_model":"({device_model}[^"]+)""",
    """"device_0_sensorName":"({sensor}[^"]+)""",
    """"device_0_type":"({device_type}[^"]+)""",
    """"device_1_ipAddress":"({device_1_src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """"device_1_id":({device_1_id}\d+)""",
    """"device_1_name":"({device_1_name}[^"]+)""",
    """"device_1_category":"({device_1_category}[^"]+)""",
    """"device_1_riskLevel":({device_1_severity}\d+)""",
    """"device_1_model":"({device_1_model}[^"]+)""",
    """"device_1_sensorName":"({device_1_sensor}[^"]+)""",
    """"device_1_type":"({device_1_type}[^"]+)""",
  ]
  DupFields = ["device_name->src_host"]
}
```