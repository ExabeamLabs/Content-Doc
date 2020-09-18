#### Parser Content
```Java
{
Name = okta-app-login-1
  Vendor = Okta
  Product = Okta Adaptive MFA
  Lms = Direct
  DataType = "app-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """Start New Session""", """"tenantHost":""" ]
  Fields = [
    """exabeam_host=({host}[^\s]+)""",
    """"userAgent":\s*"({user_agent}[^"]+)""",
    """"userAgent":\s*"[^"]*({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)[^"]+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
    """"requestTime":\s*"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """"deviceType":\s*"(login_type)""",
    """"systemAccount":\s*";*({user}[^;"]+)""",
    """"tenantHost":\s*"({app}[^"]+)""",
    """"activityAction":\s*"({activity}[^"]+)""",
    """"ipAddress":\s*"({src_ip}[^"]+)""",
    """"target":\s*\{[^\}]*"descriptor":\s*"({user}[^\/"]+?)\s*\/\s*({user_fullname}[^"]+)""",
  ]
}
```