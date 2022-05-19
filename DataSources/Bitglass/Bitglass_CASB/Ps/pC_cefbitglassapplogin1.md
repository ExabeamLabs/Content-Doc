#### Parser Content
```Java
{
Name = cef-bitglass-app-login-1
  Vendor = Bitglass
  Product = Bitglass CASB
  Lms = ArcSight
  DataType = "app-login"
  TimeFormat = "dd MMM yyyy HH:mm:ss"
  Conditions = [ """|login-success|""","""destinationServiceName =Bitglass""",""" cs6=""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """time=({time}\d{1,100} \w{1,10} \d\d\d\d \d\d:\d\d:\d\d)""",
    """\ssuser=({user_email}[^@\s]{1,2000}@({email_domain}[^\s@]{1,2000}))""",
    """({activity}login-success)""",
    """({app}Bitglass)""",
    """"ipaddress":"({src_ip}[\da-fA-F.:]{1,2000})"""",
    """"action":"({event_name}[^"]{1,2000})""",
    """"details":"({additional_info}[^"]{1,2000})""",
    """"device":"({os}[^"]{1,2000})""",
    """useragent":"({user_agent}[^"]{1,2000})"""
  ]


}
```