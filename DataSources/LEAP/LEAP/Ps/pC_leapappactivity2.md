#### Parser Content
```Java
{
Name = leap-app-activity-2
  Vendor = LEAP
  Product = LEAP
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyyMMdd:HH.mm.ss"
  Conditions = [ """,LEAPSHK,TUACCESS,""" ]
  Fields = [
    """\w+\s{1,100}\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}({host}[\w\-.]{1,2000})\s""",
    """({location}\w+),({app_code}({app}LEAPS)[^,]{0,2000}),TUACCESS,({time}[^,]{1,2000}),({user}[^,]{1,2000}),({additional_info}[^,]{1,2000}),\s{0,100}(?:({dest_ip}[a-fA-F\d.:]{1,2000})|({dest_host}.+?))\s{0,100}
```