#### Parser Content
```Java
{
Name = ur-authmgr-auth-failed-addition
  Vendor = Dell
  Product = RSA Authentication Manager
  Lms = Sumo
  DataType = "authentication-failed"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """,AUTH_FAILED_""", """,FAIL,AUTHN_METHOD_FAILED,""" ]
  Fields = [
    """exabeam_raw=.*?({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """,({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),AUTH_FAILED_[A-Z_]{1,2000},""",
    """,({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),AUTH_FAILED_[A-Z_]{1,2000},""",
    """,({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),[^,]{0,2000},AUTH_FAILED_[A-Z_]{1,2000},""",
    """,({failure_reason}[^,]{1,2000}),([^,]{0,2000},)FAIL,AUTHN_METHOD_FAILED,""",
    """AUTH_FAILED_[A-Z_]{1,2000},([^,]{0,2000},){7}({user}[^,]{1,2000})""",
    """AUTH_FAILED_[A-Z_]{1,2000},([^,]{0,2000},){12}({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """AUTH_FAILED_[A-Z_]{1,2000},([^,]{0,2000},){13}({dest_host}[^.,]{1,2000})""",
    """AUTH_FAILED_[A-Z_]{1,2000},([^,]{0,2000},){16}({auth_method}[^.,]{1,2000})"""
  ]
}
```