#### Parser Content
```Java
{
Name = kiteworks-account-unlocked-1
  Vendor = Accellion
  Product = Kiteworks
  Lms = Direct
  DataType = "account-unlocked"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """, Activity Group:""", """Activity Type: reactivate_user""", """Activity: User reactivated:""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\w+\s+\d+\s\d\d:\d\d:\d\d\s({host}[^\s]{1,2000}?)\s[^\s]{1,2000}\s({user_email}[^@]{1,2000}@({email_domain}[^\s]{1,2000}))""",
    """id=\d+\s[^\s]{1,2000}\s({src_ip}[a-fA-F\d\.:]{1,2000})""",
    """Activity Type:\s({event_name}reactivate_user)""",
    """Activity:\s({additional_info}User reactivated)""",
  ]
}
```