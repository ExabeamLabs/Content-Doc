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
    """Event Type:\s{0,100}({alert_type}[^,]{1,2000})\s{0,100}
```