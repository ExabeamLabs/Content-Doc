#### Parser Content
```Java
{
Name = symantec-security-alert-3
  Vendor = Symantec
  Product = Symantec Endpoint Protection
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """,Rule:""", """,Registry Read,Begin:""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d),({alert_severity}[^,]{1,2000}),({alert_type}[^,]{1,2000}),({host}[^,]{1,2000}),({outcome}[^,]{1,2000}),[^,]{0,2000}
```