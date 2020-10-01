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
    """,({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),AUTH_FAILED_[A-Z_]+,""",
    """,({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),AUTH_FAILED_[A-Z_]+,""",
    """,({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),[^,]*,AUTH_FAILED_[A-Z_]+,""",
    """,({failure_reason}[^,]+),([^,]*,)FAIL,AUTHN_METHOD_FAILED,""",
    """AUTH_FAILED_[A-Z_]+,([^,]*,){7}({user}[^,]+)""",
    """AUTH_FAILED_[A-Z_]+,([^,]*,){12}({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """AUTH_FAILED_[A-Z_]+,([^,]*,){13}({dest_host}[^.,]+)""",
    """AUTH_FAILED_[A-Z_]+,([^,]*,){16}({auth_method}[^.,]+)"""
  ]
}
```