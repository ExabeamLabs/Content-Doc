#### Parser Content
```Java
{
Name = entrust-identityguard-auth-failed-3
  Vendor = Entrust
  Product = IdentityGuard
  Lms = Direct
  DataType = "authentication-failed"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """] Failed authentication for user """, """Invalid response to a challenge.""", """ authentication attempts remaining.""" ]
  Fields = [
    """exabeam_time=({time}\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """\[({time}\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)(\]|,\]|,\d{1,100}\])""",
    """ user (({user_email}[^\@\s]{1,2000}@[^\s]{1,2000})|(({domain}[^\\\/]{1,2000})[\\\/]{1,2000})?({user}[^\s]{1,2000}))\. """,
    """({additional_info}Invalid response to a challenge.[^\.]{1,2000})""",
  ]
}
```