#### Parser Content
```Java
{
Name = o365-app-login-1
  Vendor = Microsoft
  Product = Office 365
  DataType = "app-login"
  Lms = Direct
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """Microsoft Office 365""", """UserLoggedIn""", """"ResultStatus":""", """,ClientIP":""" ]
  Fields = [
    """"CreationTime":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",  
    """UserId":"({user_email}[^@\s"]{1,2000}@[^@\s\."]{1,2000}\.[^\s",]{1,2000})""",
    """ClientIP":"\[?({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """Operation":"({event_name}[^",]{1,2000})""",
    """"ResultStatus":"({outcome}[^",]{1,2000})""",
    """({app}MS Office365)""",
    """"Name":"UserAgent"?,Value":"({user_agent}[^"]{1,2000}?)\s{0,100}"""",
    """DeviceProperties":\[\{"Name":"OS,Value":"({os}[^"}]{1,2000})""" 
  ]


}
```