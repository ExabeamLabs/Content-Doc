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
    """\w+\s{1,100}\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}({host}[\w\-.]+)\s""",
    """({location}\w+),({app_code}({app}LEAPS)[^,]*),TUACCESS,({time}[^,]+),({user}[^,]+),({additional_info}[^,]+),\s{0,100}(?:({dest_ip}[a-fA-F\d.:]+)|({dest_host}.+?))\s{0,100}
```