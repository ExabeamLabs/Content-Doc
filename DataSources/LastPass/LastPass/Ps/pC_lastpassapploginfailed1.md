#### Parser Content
```Java
{
Name = lastpass-app-login-failed-1
  Vendor = LastPass
  Product = LastPass
  Lms = Splunk
  DataType = "failed-app-login"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """"Data":""", """Action":"Failed Login Attempt""","""login-type":"""]
  Fields = [
    """Time":"({time}\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2})""",
    """\d\d\dZ\s({host}[\w\-.]{1,2000})""",
    """Username":"({user_email}[^@"]{1,2000}@[^"\.]{1,2000}\.[^"]{1,2000})""",
    """"src-ip":"({src_ip}[a-fA-F\d:\.]{1,2000})"""",
    """"src-application-name"{1,20}:"{1,20}({app}[^"]{1,2000})""",
    """app-user-displayname":"({user_fullname}[^"]{1,2000})""",
    """"application-action":"({activity}[^"]{1,2000})""",
    """event-name":"({event_name}[^"]{1,2000})"""
   ]


}
```