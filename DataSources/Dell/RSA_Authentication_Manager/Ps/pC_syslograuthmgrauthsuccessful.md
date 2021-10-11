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
    """,({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),[^,]{0,2000},UCM_REQUEST_AUTO_APPROVE""",
    """UCM_REQUEST_AUTO_APPROVE,([^,]{0,2000},){8}({user}[^,]{1,2000})""",
    """UCM_REQUEST_AUTO_APPROVE,([^,]{0,2000},){15}({dest_host}[^.,]{1,2000})""",
    """UCM_REQUEST_AUTO_APPROVE,([^,]{0,2000},){21}({auth_method}[^\s,]{1,2000})"""
  ]
}
```