#### Parser Content
```Java
{
Name = secureauth-app-login
    Vendor = SecureAuth
  Product = SecureAuth Login
    Lms = Direct
    DataType = "app-login"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Conditions = [ """<Priority>""","""Success</Message>""","""exabeam_raw"""]
    Fields = [
      """exabeam_raw=.*({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
	"""<UserHostAddress>({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
	"""<HostName>({host}[^<]{1,2000})""",
	"""<EventID>({event_code}\d{1,100})</EventID>""",
	"""<UserID>({user}[^<]{1,2000})""",
	"""<Realm>({app}[^<]{1,2000})""",
     	"""<UserAgent>(?:-|({user_agent}[^<]{1,2000}))""",
    ]
  

}
```