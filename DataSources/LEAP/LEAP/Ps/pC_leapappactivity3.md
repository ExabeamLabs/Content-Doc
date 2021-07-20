#### Parser Content
```Java
{
Name = leap-app-activity-3
  Vendor = LEAP
  Product = LEAP
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyyMMdd:HH.mm.ss"
  Conditions = [ """,LEAPSHK,TUAUDIT,""" ]
  Fields = [
    """\w+\s{1,100}\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}({host}[\w\-.]{1,2000})\s""",
    """({location}\w+),({app_code}({app}LEAPS)[^,]{0,2000}),TUAUDIT,({time}[^,]{1,2000}),({user}[^,]{1,2000}),[^,]{0,2000}
```