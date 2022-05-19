#### Parser Content
```Java
{
Name = cef-box-app-login
  Vendor = Box
  Product = Box Cloud Content Management
  Lms = ArcSight
  DataType = "app-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """destinationServiceName =Box""", """cs6=""", """"event_type":"LOGIN"""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """({app}Box)""",
    """({activity}login-success)""",
    """"created_at":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """\Wdproc=({process_name}[^=]{1,2000}?)(\s{1,100}\w+=|\s{0,100}$)""",
    """"ip_address":"({src_ip}[\da-fA-F.:]{1,2000})"""",
    """"login":"({user_email}[^"@]{1,2000}@({email_domain}[^@"]{1,2000}))""",
    """"event_type":"({event_name}[^"]{1,2000})"""
  ]


}
```