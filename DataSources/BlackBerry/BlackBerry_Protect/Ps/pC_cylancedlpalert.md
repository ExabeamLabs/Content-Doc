#### Parser Content
```Java
{
Name = cylance-dlp-alert
  Vendor = BlackBerry
  Product = BlackBerry Protect
  Lms = Direct
  DataType = "dlp-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """CylancePROTECT """, """Event Type: DeviceControl""", """Device Name:""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3})\d{1,100}""",
    """Event Type:\s{0,100}({alert_type}[^,]{1,2000})\s{0,100},""",
    """Event Name:\s{0,100}({alert_name}[^,]{1,2000})\s{0,100},""",
    """Device Name:\s{0,100}({src_host}[^,]{1,2000})\s{0,100},""",
    """External Device Serial Number:\s{0,100}({device_id}[^,]{1,2000})\s{0,100},""",
    """External Device Name:\s{0,100}({additional_info}[^,]{1,2000})\s{0,100},""",
    """External Device Type:\s{0,100}({device_type}[^,]{1,2000})\s{0,100},""",
  ]
}
```