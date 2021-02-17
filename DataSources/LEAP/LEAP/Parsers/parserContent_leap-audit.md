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
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """({location_country}\w+),({app_code}({app}LEAPS)[^,]*),LEAPAUDIT,({time}[^,]+),({user}[^,]+),(NULL|null|({url}[^,]+)),(NULL|null|(?:({dest_ip}[a-fA-F\d.:]+)|({dest_host}[^,]+))),({object}[^,]+),"*({activity}.+?)\s*"*,({field_name}.+?),((("(.+?)")|(.+?)),){2}({primary_key}.+?),({secondary_key}.+?),(?:[^,]+,){2}("({additional_info}[^"]+)"|({=additional_info}[^,]+))(,"*({resource}.+?)"*\s*$)?"""
  ]
}
```