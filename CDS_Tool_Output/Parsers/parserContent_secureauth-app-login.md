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
	"""<HostName>({host}[^<]+)""",
	"""<EventID>({event_code}\d+)</EventID>""",
	"""<UserID>({user}[^<]+)""",
	"""<Realm>({app}[^<]+)""",
     	"""<UserAgent>(?:-|({browser}[\w\-]+))""",
     	"""<UserAgent>(?:-|({browser}[\w\-]+)\/[\d\._]+)""",
     	"""<UserAgent>(?:-|({browser}[^\/]+).+({os}iOS|Android|BlackBerry|iPhone OS|Windows Phone|BeOS|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin))""",
      	"""<UserAgent\>(?:-|Mozilla\/.+\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident))""",
      	"""<UserAgent>(?:-|Mozilla\/.+\((?:BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+Gecko\/\d+\s+({browser}\w+))"""
    ]
  }
```