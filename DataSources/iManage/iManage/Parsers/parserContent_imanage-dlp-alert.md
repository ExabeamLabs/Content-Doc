#### Parser Content
```Java
{
Name = imanage-dlp-alert
  Vendor = iManage
  Product = iManage
  Lms = Direct
  DataType = "dlp-alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss.S"
  Conditions = [ """DOCNUM:""", """DOCUSER:""" ]
  Fields = [
    """"\s*DOCNUM:\s*"+({file_name}[^"\s]+)"+""",
    """"\s*ACTIVITY:\s*"+({alert_type}[^"\s]+)"+""",
    """"\s*ACTIVITY_DATETIME:\s*"+({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d)""",
    """"\s*DOCUSER:\s*"+({user}[^":]+)"+""",
    """"\s*APPNAME:\s*"+({app}[^":]+)"+""",
    """"\s*LOCATION:\s*"+({host}[^":]+)"+"""
  ]
}
```