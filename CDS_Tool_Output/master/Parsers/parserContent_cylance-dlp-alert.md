#### Parser Content
```Java
{
Name = cylance-dlp-alert
  Vendor = Cylance
  Product = PROTECT
  Lms = Direct
  DataType = "dlp-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """CylancePROTECT """, """Event Type: DeviceControl""", """Device Name:""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3})\d+""",
    """Event Type:\s*({alert_type}[^,]+)\s*,""",
    """Event Name:\s*({alert_name}[^,]+)\s*,""",
    """Device Name:\s*({src_host}[^,]+)\s*,""",
    """External Device Serial Number:\s*({device_id}[^,]+)\s*,""",
    """External Device Name:\s*({additional_info}[^,]+)\s*,""",
    """External Device Type:\s*({device_type}[^,]+)\s*,""",
  ]
}
```