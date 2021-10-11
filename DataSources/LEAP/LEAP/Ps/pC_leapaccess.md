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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """({location_country}\w+),({app_code}({app}LEAPS)[^,]{0,2000}),LEAPACCESS,({time}[^,]{1,2000}),({user}[^,]{1,2000}),({url}[^,]{1,2000}),\s{0,100}(?:({dest_ip}[a-fA-F\d.:]{1,2000})|({dest_host}[^,]{1,2000}?))\s{0,100},(NULL|null|({object}[^,]{1,2000}?))\s{0,100},(NULL|null|({field_name}[^,]{1,2000}?))\s{0,100},\s{0,100}"{0,20}({activity}[^,]{1,2000}?)\s{0,100}"{0,20},(?:[^,]{1,2000},){2}\s{0,100}(NULL|null|({primary_key}[^,]{1,2000}?)),\s{0,100}(NULL|null|({secondary_key}[^,]{1,2000}?)),(?:[^,]{0,2000},){2}\s{0,100}"{1,20}({additional_info}[^"]{1,2000}?)"{1,20}(,\s{0,100}"(NULL|null|({resource}[^"]{1,2000})))?""",
  ]
}
```