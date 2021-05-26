#### Parser Content
```Java
{
Name = ur-authmgr-auth-successful
  Vendor = Dell
  Product = RSA Authentication Manager
  Lms = Sumo
  DataType = "authentication-successful"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """,AUTHN_LOGIN_EVENT,13002,SUCCESS""" ]
  Fields = [
    """exabeam_raw=.*?({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """,({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),AUTHN_LOGIN_EVENT""",
    """,({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),AUTHN_LOGIN_EVENT""",
    """,({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),[^,]{0,2000}
```