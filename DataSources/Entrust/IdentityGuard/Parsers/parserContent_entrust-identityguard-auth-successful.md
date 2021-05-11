#### Parser Content
```Java
{
Name = entrust-identityguard-auth-successful
  Vendor = Entrust
  Product = IdentityGuard
  Lms = Direct
  DataType = "authentication-successful"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """] User """ , """ successfully authenticated a challenge.""", """ Authentication Type: """, """ Remote Address: """ ]
  Fields = [
    """exabeam_time=({time}\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[\w.\-]+)""",
    """\[({time}\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)(\]|,\]|,\d{1,100}\])""",
    """\] User (({user_email}[^\@\s]+@[^\s]+)|(({domain}[^\\\/]+)[\\\/]+)?({user}[^\s]+))\s""",
    """Authentication Type: ({auth_method}[^,]+),""",
    """Application Name: ({app}[^,]+),""",
    """Remote Address: ({src_ip}[a-fA-F\d\.:]+)""",
    """({additional_info}Token Used: [^,]+)""",
  ]
}
```