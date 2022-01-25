#### Parser Content
```Java
{
Name = ms-azure-signin-app-login
  Vendor = Microsoft
  Product = Azure
  Lms = Direct
  DataType = "app-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSS"
  Conditions= [ """"operationName": "Sign-in activity"""", """appDisplayName":""", """userDisplayName"""]
  Fields = [
    """time"{0,20}:\s"{0,20}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d{1,100}Z)""",
	"""tenantId"{0,20}:\s"{0,20}({host}[^\s"]{1,2000})"""",
        """errorCode"{0,20}:({error_code}\d{1,100})""",
        """failureReason"{0,20}:"{0,20}({failure_reason}[^"]{1,2000})"""",
        """"Level"{0,20}:\s{0,100}({severity}\d{1,100})""",
	"""category"{0,20}:\s{0,100}"{0,20}({category}[^"]{1,2000})"""",
	"""callerIpAddress"{0,20}:\s{0,100}"{0,20}({src_ip}[A-Fa-f:\d.]{1,2000})"""",
	"""appDisplayName"{0,20}:"{0,20}({app}[^"]{1,2000})"""",
        """"{1,20}identity"{1,20}:\s{0,100}"{1,20}({user_fullname}[^"]{1,2000})""",
        """userPrincipalName"{0,20}:"{0,20}({user_email}[^@"\s]{1,2000}?@({email_domain}[^"\s]{1,2000}?))"""",
        """"{1,20}identity"{1,20}:\s{0,100}"{1,20}({user_firstname}[^\s"]{1,2000})\s({user_lastname}[^"]{1,2000})"""",
        """userId"{0,20}:"{0,20}({uid}[^"]{1,2000})"""",
	"""operationName"{0,20}:\s"{0,20}({activity}[^"]{1,2000})"""",
	"""userAgent"{0,20}:"{0,20}({user_agent}[^"]{1,2000})"""",
	"""deviceDetail.+?displayName"{0,20}:\s{0,100}"{0,20}({object}[^"]{1,2000})"""",
        """operatingSystem.+?({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)""", 
	"""browser.+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
	"""authenticationMethod"{0,20}:"{0,20}({auth_method}[^"]{1,2000})"""",
        """"{1,20}location"{1,20}:(\{"{1,20}geoCoordinates"{1,20}:\{\}\}|({additional_info}\{.*?\}))"""
        """"{1,20}result"{1,20}:"{1,20}({outcome}[^"]{1,2000})"{1,20}""",
	]


}
```