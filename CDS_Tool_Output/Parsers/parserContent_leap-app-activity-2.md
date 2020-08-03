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
    """\w+\s+\d+\s+\d+:\d+:\d+\s+({host}[\w\-.]+)\s""",
    """({location}\w+),({app_code}({app}LEAPS)[^,]*),TUACCESS,({time}[^,]+),({user}[^,]+),({additional_info}[^,]+),\s*(?:({dest_ip}[a-fA-F\d.:]+)|({dest_host}.+?))\s*,([^,]*,){2}({activity}[^,]+),([^,]*,){4}(|({object}[^,]*?))\s*,(|({resource}[^,]*?))\s*,""",
  ]
}
```