#### Parser Content
```Java
{
Name = cb-defense-auth-successfull
  Vendor = VMware
  Product = Carbon Black Cloud Endpoint Standard
  Lms = Direct
  DataType = "authentication-successful"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """destinationServiceName=CB Defense""", """"loginName":""", """Logged in successfully""" ]
  Fields = [
    """exabeam_host=({host}[^\s]{1,2000})""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """"loginName":"(({user}[^"@]{1,2000})|({user_email}[^"]{1,2000}@[^"]{1,2000}))"""",
    """clientIp":"({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """description":"({event_name}[^"]{1,2000})""",
    """({app}CB Defense)"""
  ]
}
```