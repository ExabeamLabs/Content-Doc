#### Parser Content
```Java
{
Name = ur-authmgr-auth-failed
  Vendor = Dell
  Product = RSA Authentication Manager
  Lms = Sumo
  DataType = "authentication-failed"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """,AUTHN_LOGIN_EVENT,13002,FAIL,""" ]
  Fields = [
    """exabeam_raw=.*?({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """,({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),AUTHN_LOGIN_EVENT""",
    """,({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),AUTHN_LOGIN_EVENT""",
    """,({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),[^,]*,AUTHN_LOGIN_EVENT""",
    """,FAIL,({failure_reason}[^,]+)""",
    """AUTHN_LOGIN_EVENT,([^,]*,){7}({user}[^,]+)""",
    """AUTHN_LOGIN_EVENT,([^,]*,){12}({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """AUTHN_LOGIN_EVENT,([^,]*,){13}({dest_host}[^.,]+)""",
    """AUTHN_LOGIN_EVENT,([^,]*,){16}({auth_method}[^.,]+)"""
  ]
}
```