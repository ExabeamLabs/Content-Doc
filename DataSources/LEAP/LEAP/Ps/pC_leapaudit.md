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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """({location_country}\w+),({app_code}({app}LEAPS)[^,]{0,2000}),LEAPAUDIT,({time}[^,]{1,2000}),({user}[^,]{1,2000}),(NULL|null|({url}[^,]{1,2000})),(NULL|null|(?:({dest_ip}[a-fA-F\d.:]{1,2000})|({dest_host}[^,]{1,2000}))),({object}[^,]{1,2000}),"{0,20}({activity}.+?)\s{0,100}"{0,20},({field_name}.+?),((("(.+?)")|(.+?)),){2}({primary_key}.+?),({secondary_key}.+?),(?:[^,]{1,2000},){2}("({additional_info}[^"]{1,2000})"|({=additional_info}[^,]{1,2000}))(,"{0,20}({resource}.+?)"{0,20}\s{0,100}$)?"""
  ]
}
```