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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)"""
    """"time":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)"""
    """({alert_type}System Policy Violation)""",
    """title"\s{0,100}:\s{0,100}"({alert_name}[^"]{1,2000})""",
    """severity":"({alert_severity}[^"]{1,2000})""",
    """status":"({alert_status}[^"]{1,2000})""",
    """"deviceIds":\[({device_id_list}[^\]]{1,2000})""",
    """"device_0_ipAddress":"({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """"device_0_id":({device_id}\d{1,100})""",
    """"device_0_name":"({device_name}[^"]{1,2000})""",
    """"device_0_category":"({device_category}[^"]{1,2000})""",
    """"device_0_riskLevel":({device_severity}\d{1,100})""",
    """"device_0_model":"({device_model}[^"]{1,2000})""",
    """"device_0_sensorName":"({sensor}[^"]{1,2000})""",
    """"device_0_type":"({device_type}[^"]{1,2000})""",
    """"device_1_ipAddress":"({device_1_src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """"device_1_id":({device_1_id}\d{1,100})""",
    """"device_1_name":"({device_1_name}[^"]{1,2000})""",
    """"device_1_category":"({device_1_category}[^"]{1,2000})""",
    """"device_1_riskLevel":({device_1_severity}\d{1,100})""",
    """"device_1_model":"({device_1_model}[^"]{1,2000})""",
    """"device_1_sensorName":"({device_1_sensor}[^"]{1,2000})""",
    """"device_1_type":"({device_1_type}[^"]{1,2000})""",
  ]
  DupFields = ["device_name->src_host"]
}
```