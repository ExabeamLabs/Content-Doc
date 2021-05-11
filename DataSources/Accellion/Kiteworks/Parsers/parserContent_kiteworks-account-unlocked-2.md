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
    """\w+\s+\d+\s\d\d:\d\d:\d\d\s({host}[^\s]+?)\s""",
    """:\d\d:\d\d\s(\S+\s){2}({user_email}[^@]+@({email_domain}[^\s]+))""",
    """id=\d+\s[^\s]+\s({src_ip}[a-fA-F\d\.:]+)""",
    """Activity Type:\s({event_name}[^,]+?),""",
    """Activity:\s({additional_info}User account unlocked by lockout cooldown)""",
  ]
}
```