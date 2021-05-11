#### Parser Content
```Java
{
Name = leap-audit
  Vendor = LEAP
  Product = LEAP
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyyMMdd:HH.mm.ss"
  Conditions = [ """,LEAPAUDIT,""" ]
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """({location_country}\w+),({app_code}({app}LEAPS)[^,]*),LEAPAUDIT,({time}[^,]+),({user}[^,]+),(NULL|null|({url}[^,]+)),(NULL|null|(?:({dest_ip}[a-fA-F\d.:]+)|({dest_host}[^,]+))),({object}[^,]+),"{0,20}({activity}.+?)\s{0,100}"{0,20}
```