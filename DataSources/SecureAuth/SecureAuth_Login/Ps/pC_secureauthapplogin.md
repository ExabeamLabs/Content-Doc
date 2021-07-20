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
     	"""<UserAgent>(?:-|({browser}[\w\-]{1,2000}))""",
     	"""<UserAgent>(?:-|({browser}[\w\-]{1,2000})\/[\d\._]{1,2000})""",
     	"""<UserAgent>(?:-|({browser}[^\/]{1,2000}).+({os}iOS|Android|BlackBerry|iPhone OS|Windows Phone|BeOS|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin))""",
      	"""<UserAgent\>(?:-|Mozilla\/.+\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident))""",
      	"""<UserAgent>(?:-|Mozilla\/.+\((?:BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+Gecko\/\d{1,100}\s{1,100}({browser}\w+))"""
    ]
  }
```