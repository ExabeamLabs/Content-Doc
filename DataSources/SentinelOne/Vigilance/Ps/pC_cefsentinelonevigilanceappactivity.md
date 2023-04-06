#### Parser Content
```Java
{
Name = cef-sentinelone-vigilance-app-activity
  DataType = "app-activity"
  Conditions = [ """CEF:""", """|SentinelOne|Mgmt|""", """|Administrative information - User Deleted|""", """activityType=""", """notificationScope=""" ]
  Fields = ${SentinelOneParserTemplates.sentinelone-vigilance-app-events.Fields}[
    """({activity}User Deleted)"""
  ]

sentinelone-vigilance-app-events {
  Vendor = SentinelOne
  Product = Vigilance
  Lms = Direct
  TimeFormat = "EEE, dd MMM yyy, HH:mm:ss z"
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d),\d{1,5}(\s{1,20}\S+){2}\s{1,20}CEF:""",
    """\srt=(#arcsightDate\()?({time}\w{3},\s\d\d\s\w{1,3}\s\d\d\d\d,\s\d\d:\d\d:\d\d\s\w{3})\)?""",
    """activityType=({event_code}\d{1,20})\s\w+=""",
    """({app}SentinelOne)""",
    """suser=(({user_fullname}[^=]{1,2000}?\s[^=]{1,2000}?)|({user}[^=]{1,2000}))\s\w+="""
  
}
```