#### Parser Content
```Java
{
Name = cef-sentinelone-vigilance-app-login
  DataType = "app-login"
  Conditions = [ """CEF:""", """|SentinelOne|Mgmt|""", """|SentinelOne - New Console Login Activity""", """activityType=""", """notificationScope=""" ]
  Fields = ${SentinelOneParserTemplates.sentinelone-vigilance-app-events.Fields}[
    """\|SentinelOne\s-\sNew Console Login Activity\s{1,20}\-\s({user_email}[^@\|]{1,2000}@[^\.\|]{1,2000}\.[^\|]{1,2000}?)\s{0,20}\|""",
    """({event_name}New Console Login Activity)"""
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