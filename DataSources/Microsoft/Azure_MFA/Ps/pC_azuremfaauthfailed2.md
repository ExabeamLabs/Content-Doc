#### Parser Content
```Java
{
Name = azure-mfa-auth-failed-2
  Vendor = Microsoft
  Product = Azure MFA
  Lms = Direct
  DataType = "authentication-failed"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """|validate_oath_code: user """, """ pfsvc: """, """updated authentication result.""", """callStatus = OATH Code Incorrect""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=([^=]{1,2000}?@\s{0,100})?({host}[\w.-]{1,2000})""",
    """\w{3}\s\d\d\s\d\d:\d\d:\d\d\s({host}[^\s]{1,2000})\spfsvc:""", 
    """({event_name}validate_oath_code)""",
    """({failure_reason}OATH Code Incorrect)""",
    """user\s{1,10}(({user_email}[^@\s]{1,2000}@[^\s]{1,2000})|(({domain}[^\\\s']{1,2000})\\)?({user}[^\s']{1,2000}))\s{1,10}updated"""
    ]


}
```