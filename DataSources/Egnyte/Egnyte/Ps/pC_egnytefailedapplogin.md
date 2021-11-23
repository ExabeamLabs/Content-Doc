#### Parser Content
```Java
{
Name = egnyte-failed-app-login
  Vendor = Egnyte
  Product = Egnyte
  Lms = ArcSight
  DataType = "failed-app-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """username""", """destinationServiceName =Egnyte""", """logout_time""", """"event":"Failed Login"""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}?@\s{0,100})?({host}[\w.-]{1,2000})""",
    """"time":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)Z"""",
    """requestClientApplication=({app}[^=]{1,2000}?)\s\w+=""",
    """dproc=({dproc}[^=]{1,2000})\s\w+=""",
    """ipAddress":"({src_ip}[a-fA-F\d.:]{1,2000})""",
    """ip_address":"({src_ip}[a-fA-F\d.:]{1,2000})""",
    """destinationServiceName =({event_subtype}[^=]{1,2000})\s\w+=""",
    """([^\|]{0,2000}\|){5}({activity}[^\|]{1,2000})\|""",
    """"username":"({user_fullname}[^\(]{1,2000})\s\(\s{0,100}({user_email}[^@]{1,2000}@({email_domain}[^\s\)]{1,2000}))\s{0,100}\)"""",
    """"event":"({event_name}[^"]{1,2000})""""
  ]
  DupFields = [ "dproc->category" ]


}
```