#### Parser Content
```Java
{
Name = json-ping-id-auth-failed
  Vendor = Ping Identity
  Product = Ping Identity
  Lms = Direct
  DataType = "authentication-failed"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """"application-msg":""", """SSO Invalid SMS Passcode""", """"triggered-by":""", """Ping""" ]
  Fields = [
    """time"+:"+({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)"""
    """"+hostname"+:"+({host}[^"]+)""",
    """app-username"+:"+(({user_email}[^@\s"]+@[^"\s]+)|({user}[^"\s]+))""",
    """"src-application-name"+:"+({app}[^"]+)""",
    """"application-msg"+:"+({failure_reason}[^}\]]+?)\s*"[,\]}]"""
  ]
}
```