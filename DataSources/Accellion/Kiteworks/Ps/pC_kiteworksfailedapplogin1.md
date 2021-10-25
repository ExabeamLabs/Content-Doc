#### Parser Content
```Java
{
Name = kiteworks-failed-app-login-1
  Vendor = Accellion
  Product = Kiteworks
  Lms = Direct
  DataType = "failed-app-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """, Activity Group:""", """Activity Type: user_login_failed""", """login failed""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\w+\s{1,100}\d{1,100}\s\d\d:\d\d:\d\d\s({host}[^\s]{1,2000}?)\s[^\s]{1,2000}([^=]{1,2000}=[^,]{1,2000},)?\s({src_ip}[a-fA-F\d\.:]{1,2000})""",
    """User:\s{1,10}(({user_email}[^@\s]{1,2000}@({email_domain}[^\s\.]{1,2000}\.[^\s]{1,2000}))|({user}[^\s@]{1,2000})(@({domain}[^\s]{1,2000}))?)\s({additional_info}login failed)""",
    """Activity Type:\s({event_name}user_login_failed)""",
  ]
}
```