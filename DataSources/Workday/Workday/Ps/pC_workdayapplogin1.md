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
    """exabeam_host=({host}[^\s]{1,2000})""",
    """"userAgent":\s{0,100}"({user_agent}[^"]{1,2000})""",
    """"userAgent":\s{0,100}"[^"]{0,2000}({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)[^"]{1,2000}?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
    """"requestTime":\s{0,100}"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """"deviceType":\s{0,100}"({device_type}[^"]{1,2000})""",
    """"systemAccount":\s{0,100}"({user}[^"]{1,2000})""",
    """({app}(W|w)orkday)"""
    """"tenantHost":\s{0,100}"({host}[^"]{1,2000})""",
    """"activityAction":\s{0,100}"({additional_info}[^"]{1,2000})""",
    """"taskDisplayName":\s{0,100}"({activity}[^"]{1,2000})"""
    """"ipAddress":\s{0,100}"({src_ip}[^"]{1,2000})""",
    """"target":\s{0,100}\{[^\}]{0,2000}"descriptor":\s{0,100}"({user}[^\/"]{1,2000}?)\s{0,100}\/\s{0,100}({user_fullname}[^"]{1,2000})""",
  ]
}
```