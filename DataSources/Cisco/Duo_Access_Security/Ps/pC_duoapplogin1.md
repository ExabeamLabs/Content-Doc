#### Parser Content
```Java
{
Name = duo-app-login-1
  Vendor = Cisco
  Product = Duo Access Security
  Lms = Direct
  DataType = "app-login"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ duo:""", """|admin_login|""", """"ip_address":""", """"primary_auth_method":""" ]
  Fields = [
    """:\d\d:\d\d ({host}[\w.-]{1,2000})\sduo:""",
    """\sduo:\s({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """({app}duo)""",
    """\sduo:\s[^\|]{1,200}\|({user_fullname}({user_firstname}[^\s\|]{1,2000})\s({user_lastname}[^\|]{1,2000}))""",
    """device":\s{0,100}"({object}[^"]{1,2000})""",
    """"ip_address":\s{0,100}"({src_ip}[a-fA-F\d.:]{1,2000})"""",
    """"primary_auth_method":\s{0,100}"({auth_method}[^"]{1,2000}?)"""",
    """"factor":\s{0,100}"({action}[^"]{1,2000}?)"""",
    """({activity}admin_login)"""
  ]
  DupFields = ["activity->event_name"]


}
```