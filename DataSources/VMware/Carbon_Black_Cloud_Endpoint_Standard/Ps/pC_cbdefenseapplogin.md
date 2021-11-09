#### Parser Content
```Java
{
Name = cb-defense-app-login
  Vendor = VMware
  Product = Carbon Black Cloud Endpoint Standard
  Lms = Direct
  DataType = "app-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """destinationServiceName=CB Defense""", """"loginName":""", """logged in successfully""" ]
  Fields = [
    """exabeam_host=({host}[\w\-.]{1,2000})""",   
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """"loginName":"(({user}[^"@]{1,2000})|({user_email}[^"]{1,2000}@[^"]{1,2000}))"""",
    """clientIp":"({src_ip}[a-fA-F\d.:]{1,2000})""",
    """description":"({event_name}[^"]{1,2000})""",
    """({app}CB Defense)"""
  ]
}
}
```