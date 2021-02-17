#### Parser Content
```Java
{
Name = armis-security-alert
  Vendor = Armis
  Product = Armis
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """"relatedDevices":""", """"actionType":""" , """"identifier":""", """ armis """ ]
  Fields = [
    """\d+-\d+-\d+T\d+:\d+:\d+\.\d+[\+\-]\d+:\d+\s+({host}[\w\-.]+)\s+armis""",
    """_time"\s*:\s*"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """"name":\s*"({src_host}[\w\-.]+)"""",
    """"title":.+?type"\s*:\s*"({alert_type}[^"]+)"""
    """"category":\s*"(UNKNOWN|({alert_type}[^"]+))"""",
    """"type":\s*"(UNKNOWN|({device_type}[^"]+))"""",
    """"model":\s*"(Unknown model|({device_type}[^"]+))"""",
    """"identifier":\s*"({device_identifier}[^"]+)"""",
    """"ip":\s*"({src_ip}[A-Fa-f:\d.]+)"""",
    """"actionType":\s*"({alert_severity}[^"]+)"""",
    """"title":\s*"({alert_name}[^"]+)"""",
    """"timezone":\s*"({time_zone}[^"]+)"""",
  ]
}
```