#### Parser Content
```Java
{
Name = egnyte-failed-app-login
  Vendor = Egnyte
  Product = Egnyte
  Lms = ArcSight
  DataType = "failed-app-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """|Skyformation|""", """|login-failed|""", """destinationServiceName =Egnyte""", """CEF:""", """sk4-login-failure""", """"event":"Failed Login"""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}?@\s{0,100})?({host}[\w.-]{1,2000})""",
    """"time":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)Z"""",
    """msg=({additional_info}[^=]{1,2000}?)\s\w+=""",
    """requestClientApplication=({app}[^=]{1,2000}?)\s\w+=""",
    """dproc=({dproc}[^=]{1,2000})\s\w+=""",
    """src=({src_ip}[a-fA-F\d:.]{1,2000})""",
    """suser=({user_email}[^@]{1,2000}@({email_domain}[^\s]{1,2000}))\s\w+=""",
    """destinationServiceName =({event_subtype}[^=]{1,2000})\s\w+=""",
    """dtz=({dtz}[^=]{1,2000})\s\w+=""",
    """([^\|]{0,2000}\|){5}({activity}[^\|]{1,2000})\|""",
    """"username":"({user_fullname}[^\(]{1,2000})\s\(\s{0,100}({user_email}[^@]{1,2000}@({email_domain}[^\s\)]{1,2000}))\s{0,100}\)"""",	
    """cat=({category}[^=]{1,2000})\s\w+=""",
    """"event":"({event_name}[^"]{1,2000})""""
  ]


}
```