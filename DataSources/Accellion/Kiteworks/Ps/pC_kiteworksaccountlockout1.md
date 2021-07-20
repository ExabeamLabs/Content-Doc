#### Parser Content
```Java
{
Name = kiteworks-account-lockout-1
  Vendor = Accellion
  Product = Kiteworks
  Lms = Direct
  DataType = "account-lockout"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """, Activity Group:""", """Activity Type: user_login_lockout,""", """Activity: User account locked""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\w+\s{1,100}\d{1,100}\s\d\d:\d\d:\d\d\s({host}[^\s]{1,2000}?)\s[^\s]{1,2000}\s({user_email}[^@]{1,2000}@({email_domain}[^\s]{1,2000}))""",
    """id=\d{1,100}\s[^\s]{1,2000}\s({src_ip}[a-fA-F\d\.:]{1,2000})""",
    """Activity Type:\s({event_name}user_login_lockout)""",
    """Activity:\s({additional_info}User account locked)""",
  ]
}
```