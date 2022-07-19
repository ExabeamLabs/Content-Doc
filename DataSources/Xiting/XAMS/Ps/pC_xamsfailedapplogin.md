#### Parser Content
```Java
{
Name = xams-failed-app-login
  Vendor = Xiting
  Product = XAMS
  Lms = Splunk
  DataType = "failed-app-login"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """Login gescheitert""", """CEF:""", """|Xiting|XAMS|""", """"USERID":"""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}?@\s{0,100})?({host}[\w.-]{1,2000})""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """"USERID":"({user}[^"]{1,2000})"""",
    """({app}XAMS)""",
    """({event_name}Login gescheitert)"""
    """"MSG":"({additional_info}[^"]{1,2000})""""
  ]


}
```