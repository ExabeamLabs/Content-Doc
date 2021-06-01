#### Parser Content
```Java
{
Name = kiteworks-password-change-1
  Vendor = Accellion
  Product = Kiteworks
  Lms = Direct
  DataType = "password-change"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """, Activity Group:""", """Activity Type: reset_password,""", """Activity: Reset password""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\w+\s{1,100}\d{1,100}\s\d\d:\d\d:\d\d\s({host}[^\s]{1,2000}?)\s[^\s]{1,2000}\s({user_email}[^@]{1,2000}@({email_domain}[^\s]{1,2000}))""",
    """id=\d{1,100}\s[^\s]{1,2000}\s({src_ip}[a-fA-F\d\.:]{1,2000})""",
    """Activity Type:\s({event_name}reset_password)""",
    """Activity:\s({additional_info}Reset password)""",
  ]
}
```