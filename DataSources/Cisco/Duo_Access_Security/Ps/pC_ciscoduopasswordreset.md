#### Parser Content
```Java
{
Name = cisco-duo-password-reset
  Vendor = Cisco
  Product = Duo Access Security
  Lms = Direct
  DataType = "account-password-reset"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ duo: """, """|reset_admin_auth_attempts|""", """": """" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}?@\s{0,100})?({host}[\w.-]{1,2000})""",
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """:\d\d\|({user_fullname}[^\|]{0,2000})\|(|({target_user}[^\|]{1,2000}))\|({event_name}[^\|]{1,2000})\|""",
    """"message":\s{0,100}"({additional_info}[^"]{1,2000}?)"""",
    """({app}duo)""",
  ]


}
```