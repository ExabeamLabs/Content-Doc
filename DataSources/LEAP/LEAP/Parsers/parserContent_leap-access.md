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
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """({location_country}\w+),({app_code}({app}LEAPS)[^,]*),LEAPACCESS,({time}[^,]+),({user}[^,]+),({url}[^,]+),\s*(?:({dest_ip}[a-fA-F\d.:]+)|({dest_host}.+?))\s*,(NULL|null|({object}.+?))\s*,(NULL|null|({field_name}.+?))\s*,\s*"*({activity}.+?)\s*"*,(?:[^,]+,){2}\s*(NULL|null|({primary_key}.+?)),\s*(NULL|null|({secondary_key}.+?)),(?:[^,]*,){2}\s*"({additional_info}.+?)"(,\s*"(NULL|null|({resource}[^"]+)))?"""
  ]
}
```