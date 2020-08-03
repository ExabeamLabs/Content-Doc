#### Parser Content
```Java
{
Name = ur-authmgr-account-lockout
  Vendor = Dell EMC
  Product = RSA Authentication Manager
  Lms = Sumo
  DataType = "account-lockout"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """,AUTHN_LOCKOUT_EVENT,""", """,SUCCESS,""" ]
  Fields = [
    """exabeam_raw=.*?({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """,({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),AUTHN_LOCKOUT_EVENT""",
    """,({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),AUTHN_LOCKOUT_EVENT""",
    """,({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),[^,]*,AUTHN_LOCKOUT_EVENT""",
    """AUTHN_LOCKOUT_EVENT,([^,]*,){7}({user}[^,]+)""",
    """AUTHN_LOCKOUT_EVENT,([^,]*,){12}({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """AUTHN_LOCKOUT_EVENT,([^,]*,){13}({dest_host}[^.,]+)""",
    """AUTHN_LOCKOUT_EVENT,([^,]*,){13}[^.,]+\.({domain}[^.,]+)""",
    """AUTHN_LOCKOUT_EVENT,([^,]*,){16}({auth_method}[^.,]+)"""
  ]
}
```