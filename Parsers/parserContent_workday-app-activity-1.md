#### Parser Content
```Java
{
Name = workday-app-activity-1
  Vendor = Workday
  Product = Workday
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"activityAction":""", """"tenantHost":""" , """workday"""]
  Fields = [
    """exabeam_host=({host}[^\s]+)""",
    """"userAgent":\s*"({user_agent}[^"]+)""",
    """"userAgent":\s*"[^"]*({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)[^"]+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
    """"requestTime":\s*"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """"deviceType":\s*"({device_type}[^"]+)""",
    """"systemAccount":\s*";*({user}[^;"]+)""",
    """"tenantHost":\s*"({host}[^"]+)""",
    """"activityAction":\s*"({additional_info}[^"]+)""",
    """"ipAddress":\s*"({src_ip}[^"]+)""",
    """"target":\s*\{[^\}]*"descriptor":\s*"({object}[^"]+?)"""",
    """"taskDisplayName":\s*"({activity}[^"]+)"""
    """({app}(W|w)orkday)"""
  ]
}
```