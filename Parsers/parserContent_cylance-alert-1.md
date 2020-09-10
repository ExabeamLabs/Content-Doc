#### Parser Content
```Java
{
Name = cylance-alert-1
  Vendor = Cylance
  Product = PROTECT
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """CylancePROTECT""", """Event Type: ScriptControl""","""Interpreter: """]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """\[({host}[\w\-.]+)\]\s*Event Type:""",
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d{3})\d+""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3})\d+""",
    """Event Type:\s*({alert_type}[^,]+)\s*,""",
    """Event Name:\s*({additional_info}[^,]+)\s*,""",
    """Device Name:\s*({src_host}[^,]+)\s*,""",
    """File Path:\s*({malware_url}[^,]+)\s*,""",
    """Interpreter:\s*({alert_name}[^,]+)\s*,""",
    """User Name:\s*(?:SYSTEM|({user}[^,]+?))\s*(,|$)"""
  ]
  DupFields = [ "malware_url->malware_file_name" ]
}
```