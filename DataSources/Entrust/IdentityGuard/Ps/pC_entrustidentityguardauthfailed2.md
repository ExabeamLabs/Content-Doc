#### Parser Content
```Java
{
Name = entrust-identityguard-auth-failed-2
  Vendor = Entrust
  Product = IdentityGuard
  Lms = Direct
  DataType = "authentication-failed"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """] User """ , """ failed authentication.""", """ Authentication Type: """, """ Application Name: """, """ Remote Address: """ ]
  Fields = [
    """exabeam_time=({time}\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """\[({time}\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)(\]|,\]|,\d{1,100}\])""",
    """ User (({user_email}[^\@\s]{1,2000}@[^\s]{1,2000})|(({domain}[^\\\/]{1,2000})[\\\/]{1,2000})?({user}[^\s]{1,2000})) failed authentication""",
    """Authentication Type: ({auth_method}[^,]{1,2000}),""",
    """Application Name: ({app}[^,]{1,2000}),""",
    """Remote Address: ({src_ip}[a-fA-F\d\.:]{1,2000})""",
  ]
}
```