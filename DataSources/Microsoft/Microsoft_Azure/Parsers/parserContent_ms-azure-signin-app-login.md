#### Parser Content
```Java
{
Name = ms-azure-signin-app-login
  Vendor = Microsoft
  Product =  Microsoft Azure
  Lms = Direct
  DataType = "app-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSS"
  Conditions= [ """"operationName": "Sign-in activity"""", """appDisplayName":""", """userDisplayName"""]
  Fields = [
    """time"*:\s"*({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d+Z)""",
	"""tenantId"*:\s"*({host}[^\s"]+)"""",
        """errorCode"*:({error_code}\d+)""",
        """failureReason"*:"*({failure_reason}[^"]+)"""",
        """"Level"*:\s*({severity}\d+)""",
	"""category"*:\s*"*({category}[^"]+)"""",
	"""callerIpAddress"*:\s*"*({src_ip}[A-Fa-f:\d.]+)"""",
	"""appDisplayName"*:"*({app}[^"]+)"""",
        """"+identity"+:\s*"+({user_fullname}[^"]+)""",
        """userPrincipalName"*:"*({user_email}[^@"\s]+?@({email_domain}[^"\s]+?))"""",
        """"+identity"+:\s*"+({user_firstname}[^\s"]+)\s({user_lastname}[^"]+)"""",
        """userId"*:"*({uid}[^"]+)"""",
	"""operationName"*:\s"*({activity}[^"]+)"""",
	"""userAgent"*:"*({user_agent}[^"]+)"""",
	"""deviceDetail.+?displayName"*:\s*"*({object}[^"]+)"""",
        """operatingSystem.+?({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)""", 
	"""browser.+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
	"""authenticationMethod"*:"*({auth_method}[^"]+)"""",
        """"+location"+:(\{"+geoCoordinates"+:\{\}\}|({additional_info}\{.*?\}))"""
        """"+result"+:"+({outcome}[^"]+)"+""",
	]
}
```