#### Parser Content
```Java
{
Name = json-ping-id-auth-failed-2
  Vendor = Ping Identity
  Product = Ping Identity
  Lms = Direct
  DataType = "authentication-failed"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """"application-msg":""", """SSO Auth. Canceled from server""", """"triggered-by":""", """Ping""" ]
  Fields = [
    """time"{1,20}:"{1,20}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)"""
    """"{1,20}hostname"{1,20}:"{1,20}({host}[^"]{1,2000})""",
    """app-username"{1,20}:"{1,20}(({user_email}[^@\s"]{1,2000}@[^"\s]{1,2000})|({user}[^"\s]{1,2000}))""",
    """"src-application-name"{1,20}:"{1,20}({app}[^"]{1,2000})""",
    """"application-msg"{1,20}:"{1,20}({failure_reason}[^}\]]{1,2000}?)\s{0,100}"[,\]}]"""
  ]
}
```