#### Parser Content
```Java
{
Name = cef-sentinelone-vigilance-security-alert
  Conditions = [ """CEF:""", """|SentinelOne|Mgmt|""", """|New active threat""", """activityType=""", """notificationScope=""" ]

sentinelone-vigilance-alerts {
    Vendor = SentinelOne
    Product = Vigilance
    Lms = Direct
    DataType = "alert"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSS"
    Fields = [
      """({time}\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d),\d{1,5}(\s{1,20}\S+){2}\s{1,20}CEF:""",
      """\srt=({time}\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d\.\d{1,6})\s""",
      """\smachine\s({dest_host}[\w\-\.]{1,2000})\|""",
      """activityType=({event_code}\d{1,20})\s\w+=""",
      """\|SentinelOne\|Mgmt\|([^\|]{1,2000}\|){2}({alert_name}[^\|\-]{1,2000})\s\-""",
      """\|SentinelOne\|Mgmt\|([^\|]{1,2000}\|){3}({alert_severity}\d{1,2})""",
      """activityID=({alert_id}\d{1,100})\s\w+=""",
      """\scat=({alert_type}\S+)""",
      """fileHash=({sha1}[^\s]{1,2000})\s\w+=""",
      """filePath=({file_path}({file_parent}[^=]{1,2000}?)[\\\/]{1,20}({file_name}[^=\/\\]{1,2000}?(\.({file_ext}[^=\/\\]{1,2000}))?))\s\w+="""
    
}
```