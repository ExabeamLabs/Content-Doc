#### Parser Content
```Java
{
Name = json-ping-id-auth-failed-1
  Vendor = Ping Identity
  Product = Ping Identity
  Lms = Direct
  DataType = "authentication-failed"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """"application-msg":""", """SSO Auth. Timed Out""", """"triggered-by":""", """Ping""" ]
  Fields = [
    """time"{1,20}:"{1,20}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)"""
    """"{1,20}hostname"{1,20}:"{1,20}({host}[^"]+)""",
    """app-username"{1,20}:"{1,20}(({user_email}[^@\s"]+@[^"\s]+)|({user}[^"\s]+))""",
    """"src-application-name"{1,20}:"{1,20}({app}[^"]+)""",
    """"application-msg"{1,20}:"{1,20}({failure_reason}[^}\]]+?)\s{0,100}"[,\]}]"""
  ]
}
```