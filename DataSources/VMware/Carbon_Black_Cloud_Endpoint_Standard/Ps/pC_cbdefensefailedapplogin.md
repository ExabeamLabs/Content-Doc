#### Parser Content
```Java
{
Name = cb-defense-failed-app-login
  Vendor = VMware
  Product = Carbon Black Cloud Endpoint Standard
  Lms = Direct
  DataType = "failed-app-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """destinationServiceName=CB Defense""", """"loginName":""", """Login failed""" ]
  Fields = [
    """exabeam_host=({host}[^\s]{1,2000})""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """"loginName":"(({user}[^"@]{1,2000})|({user_email}[^"]{1,2000}@[^"]{1,2000}))"""",
    """clientIp":"({src_ip}[a-fA-F\d.:]{1,2000})""",
    """description":"({failure_reason}[^"]{1,2000})""",
    """({app}CB Defense)""",
  ]
}
```