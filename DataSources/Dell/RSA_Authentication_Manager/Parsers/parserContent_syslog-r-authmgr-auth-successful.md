#### Parser Content
```Java
{
Name = syslog-r-authmgr-auth-successful
  Vendor = Dell
  Product = RSA Authentication Manager
  Lms = Direct
  DataType = "authentication-successful"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """,UCM_REQUEST_AUTO_APPROVE,""", """,SUCCESS,""" ]
  Fields = [
    """exabeam_raw=.*?({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """,({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),UCM_REQUEST_AUTO_APPROVE""",
    """,({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),[^,]{0,2000}
```