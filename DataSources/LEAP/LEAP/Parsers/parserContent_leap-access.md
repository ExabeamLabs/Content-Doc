#### Parser Content
```Java
{
Name = leap-access
  Vendor = LEAP
  Product = LEAP
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyyMMdd:HH.mm.ss"
  Conditions = [ """,LEAPACCESS,""" ]
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """({location_country}\w+),({app_code}({app}LEAPS)[^,]*),LEAPACCESS,({time}[^,]+),({user}[^,]+),({url}[^,]+),\s{0,100}(?:({dest_ip}[a-fA-F\d.:]+)|({dest_host}.+?))\s{0,100}
```