#### Parser Content
```Java
{
Name = egnyte-app-login
  Vendor = Egnyte
  Product = Egnyte
  Lms = ArcSight
  DataType = "app-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """|Skyformation|""", """|login-success|""", """destinationServiceName=Egnyte""", """CEF:""", """sk4-login-success""", """"event":"Login""""]
  Fields = [
    """exabeam_host=([^=]+?@\s{0,100})?({host}[\w.-]+)""",
    """"time":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)Z"""",
    """msg=({additional_info}[^=]+?)\s\w+=""",
    """requestClientApplication=({app}[^=]+?)\s\w+=""",
    """dproc=({dproc}[^=]+)\s\w+=""",
    """src=({src_ip}[a-fA-F\d:.]+)""",
    """suser=({user_email}[^@]+@({email_domain}[^\s]+))\s\w+=""",
    """destinationServiceName=({event_subtype}[^=]+)\s\w+=""",
    """dtz=({dtz}[^=]+)\s\w+=""",
    """([^\|]*\|){5}({activity}[^\|]+)\|""",
    """"username":"({user_fullname}[^\(]+)\s\(\s{0,100}({user_email}[^@]+@({email_domain}[^\s\)]+))\s{0,100}\)"""",	
    """cat=({category}[^=]+)\s\w+=""",
    """"event":"({event_name}[^"]+)""""
  ]
}
```