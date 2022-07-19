#### Parser Content
```Java
{
Name = xams-app-login
  Vendor = Xiting
  Product = XAMS
  Lms = Splunk
  DataType = "app-login"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """Login erfolgreich""", """CEF:""", """|Xiting|XAMS|""", """"USERID":"""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}?@\s{0,100})?({host}[\w.-]{1,2000})""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """"USERID":"({user}[^"]{1,2000})"""",
    """({app}XAMS)""",
    """({event_name}Login erfolgreich)"""
    """"MSG":"({additional_info}[^"]{1,2000})""""
  ]


}
```