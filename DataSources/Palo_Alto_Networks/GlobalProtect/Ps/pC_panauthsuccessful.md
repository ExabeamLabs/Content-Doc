#### Parser Content
```Java
{
Name = pan-auth-successful
  Vendor = Palo Alto Networks
  Product = GlobalProtect
  Lms = Direct
  DataType = "authentication-successful"
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [ """,SYSTEM,auth,""", """,auth-success,""" ]
  Fields = [
    """SYSTEM,auth,[^,]{1,2000},({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z),""",
    """:\d\d:\d\d\s{1,100}({host}[\w.-]{1,2000})\s""",
    """\w+\s{1,100}\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}({host}[\w\-.]{1,2000})\s{1,100}\d{1,100},({time}\d{1,100}\/\d{1,100}\/\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}),""",
    """,auth-success,({auth_method}[^,]{1,2000})""",
    """\suser '(({user}[^@',]{1,2000})@({domain}[^@.,']{1,2000}\.lan)|({user_email}[^@\s']{1,2000}@[^.']{1,2000}\.[^']{1,2000})|({=user}[^\s']{1,2000}))'""",
    """"authenticated for user '({user}[^\s']{1,2000})""",
    """From:\s{0,100}(({src_ip}[A-Fa-f:\d.]{1,2000}?)|({src_host}.+?))\.?"""",
    """({event_name}auth-success)""",
    """auth-success,([^,]{0,2000},){5}"?({additional_info}[^,']{1,2000}?)\s'""",
    """,SYSTEM,("[^"]{1,2000}",|[^,]{0,2000},){18}({dest_host}[\w\-.]{1,2000})"""
  ]
}
```