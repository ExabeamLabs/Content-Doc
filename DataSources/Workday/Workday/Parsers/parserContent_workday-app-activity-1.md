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
    """"userAgent":\s{0,100}"({user_agent}[^"]+)""",
    """"userAgent":\s{0,100}"[^"]*({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)[^"]+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
    """"requestTime":\s{0,100}"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """"deviceType":\s{0,100}"({device_type}[^"]+)""",
    """"systemAccount":\s{0,100}";*({user}[^;"]+)""",
    """"tenantHost":\s{0,100}"({host}[^"]+)""",
    """"activityAction":\s{0,100}"({additional_info}[^"]+)""",
    """"ipAddress":\s{0,100}"({src_ip}[^"]+)""",
    """"target":\s{0,100}\{[^\}]*"descriptor":\s{0,100}"({object}[^"]+?)"""",
    """"taskDisplayName":\s{0,100}"({activity}[^"]+)"""
    """({app}(W|w)orkday)"""
  ]
}
```