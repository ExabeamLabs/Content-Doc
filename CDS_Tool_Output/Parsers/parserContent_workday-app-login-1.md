#### Parser Content
```Java
{
Name = workday-app-login-1
  Vendor = Workday
  Product = Workday
  Lms = Direct
  DataType = "app-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """Start New Session""", """"tenantHost":""" , """workday"""]
  Fields = [
    """exabeam_host=({host}[^\s]+)""",
    """"userAgent":\s*"({user_agent}[^"]+)""",
    """"userAgent":\s*"[^"]*({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)[^"]+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
    """"requestTime":\s*"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """"deviceType":\s*"({device_type}[^"]+)""",
    """"systemAccount":\s*"({user}[^"]+)""",
    """({app}(W|w)orkday)"""
    """"tenantHost":\s*"({host}[^"]+)""",
    """"activityAction":\s*"({additional_info}[^"]+)""",
    """"taskDisplayName":\s*"({activity}[^"]+)"""
    """"ipAddress":\s*"({src_ip}[^"]+)""",
    """"target":\s*\{[^\}]*"descriptor":\s*"({user}[^\/"]+?)\s*\/\s*({user_fullname}[^"]+)""",
  ]
}
```