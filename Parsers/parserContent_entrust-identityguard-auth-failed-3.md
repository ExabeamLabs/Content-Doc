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
    """exabeam_host=({host}[\w.\-]+)""",
    """\[({time}\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)(\]|,\]|,\d+\])""",
    """ user (({user_email}[^\@\s]+@[^\s]+)|(({domain}[^\\\/]+)[\\\/]+)?({user}[^\s]+))\. """,
    """({additional_info}Invalid response to a challenge.[^\.]+)""",
  ]
}
```