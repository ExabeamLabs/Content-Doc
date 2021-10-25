#### Parser Content
```Java
{
Name = kiteworks-account-unlocked-2
  Vendor = Accellion
  Product = Kiteworks
  Lms = Direct
  DataType = "account-unlocked"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """, Activity Group:""", """Activity Type: user_login_unlock,""",  """Activity: User account unlocked""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\w+\s{1,100}\d{1,100}\s\d\d:\d\d:\d\d\s({host}[^\s]{1,2000}?)\s[^\s]{1,2000}\s({user_email}[^@]{1,2000}@({email_domain}[^\s]{1,2000}))""",
    """id=\d{1,100}\s[^\s]{1,2000}\s({src_ip}[a-fA-F\d\.:]{1,2000})""",
    """Activity Type:\s({event_name}[^,]{1,2000}?),""",
    """Activity:\s({additional_info}User account unlocked by lockout cooldown)""",
  ]
}
```