#### Parser Content
```Java
{
Name = egnyte-failed-app-login
  Vendor = Egnyte
  Product = Egnyte
  Lms = ArcSight
  DataType = "failed-app-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """|Skyformation|""", """|login-failed|""", """destinationServiceName=Egnyte""", """CEF:""", """sk4-login-failure""", """"event":"Failed Login"""" ]
  Fields = [
    """exabeam_host=([^=]+?@\s*)?({host}[\w.-]+)""",
    """"time":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)Z"""",
    """msg=({additional_info}[^=]+?)\s\w+=""",
    """requestClientApplication=({app}[^=]+?)\s\w+=""",
    """dproc=({dproc}[^=]+)\s\w+=""",
    """src=({src_ip}[a-fA-F\d:.]+)""",
    """suser=({user_email}[^@]+@({email_domain}[^\s]+))\s\w+=""",
    """destinationServiceName=({event_subtype}[^=]+)\s\w+=""",
    """dtz=({dtz}[^=]+)\s\w+=""",
    """([^\|]*\|){5}({activity}[^\|]+)\|""",
    """"username":"({user_fullname}[^\(]+)\s\(\s*({user_email}[^@]+@({email_domain}[^\s\)]+))\s*\)"""",	
    """cat=({category}[^=]+)\s\w+=""",
    """"event":"({event_name}[^"]+)""""
  ]
}
```