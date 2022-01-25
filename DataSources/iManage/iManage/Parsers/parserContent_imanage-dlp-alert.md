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
    """"\s{0,100}DOCNUM:\s{0,100}"{1,20}({file_name}[^"\s]{1,2000})"{1,20}""",
    """"\s{0,100}ACTIVITY:\s{0,100}"{1,20}({alert_type}[^"\s]{1,2000})"{1,20}""",
    """"\s{0,100}ACTIVITY_DATETIME:\s{0,100}"{1,20}({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d)""",
    """"\s{0,100}DOCUSER:\s{0,100}"{1,20}({user}[^":]{1,2000})"{1,20}""",
    """"\s{0,100}APPNAME:\s{0,100}"{1,20}({app}[^":]{1,2000})"{1,20}""",
    """"\s{0,100}LOCATION:\s{0,100}"{1,20}({host}[^":]{1,2000})"{1,20}"""
  ]
}
```