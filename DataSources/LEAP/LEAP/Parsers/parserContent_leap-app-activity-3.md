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
    """\w+\s{1,100}\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}({host}[\w\-.]+)\s""",
    """({location}\w+),({app_code}({app}LEAPS)[^,]*),TUAUDIT,({time}[^,]+),({user}[^,]+),[^,]*,\s{0,100}(?:|NULL|({dest_ip}[a-fA-F\d.:]+)|({dest_host}.+?))\s{0,100}
```