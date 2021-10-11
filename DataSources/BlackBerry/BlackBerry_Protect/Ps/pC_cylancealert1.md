#### Parser Content
```Java
{
Name = cylance-alert-1
  Vendor = BlackBerry
  Product = BlackBerry Protect
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """CylancePROTECT""", """Event Type: ScriptControl""","""Interpreter: """]
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """\[({host}[\w\-.]{1,2000})\]\s{0,100}Event Type:""",
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d{3})\d{1,100}""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3})\d{1,100}""",
    """Event Type:\s{0,100}({alert_type}[^,]{1,2000})\s{0,100},""",
    """Event Name:\s{0,100}({additional_info}[^,]{1,2000})\s{0,100},""",
    """Device Name:\s{0,100}({src_host}[^,]{1,2000})\s{0,100},""",
    """File Path:\s{0,100}({malware_url}[^,]{1,2000})\s{0,100},""",
    """Interpreter:\s{0,100}({alert_name}[^,]{1,2000})\s{0,100},""",
    """User Name:\s{0,100}(?:SYSTEM|({user}[^,]{1,2000}?))\s{0,100}(,|$)"""
  ]
  DupFields = [ "malware_url->malware_file_name" ]
}
```