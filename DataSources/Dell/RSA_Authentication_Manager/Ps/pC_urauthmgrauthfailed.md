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
    """,({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),[^,]{0,2000},AUTHN_LOGIN_EVENT""",
    """,FAIL,({failure_reason}[^,]{1,2000})""",
    """AUTHN_LOGIN_EVENT,([^,]{0,2000},){7}({user}[^,]{1,2000})""",
    """AUTHN_LOGIN_EVENT,([^,]{0,2000},){12}({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """AUTHN_LOGIN_EVENT,([^,]{0,2000},){13}({dest_host}[^.,]{1,2000})""",
    """AUTHN_LOGIN_EVENT,([^,]{0,2000},){16}({auth_method}[^.,]{1,2000})"""
  ]
}
```