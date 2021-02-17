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
    """\w+\s+\d+\s+\d+:\d+:\d+\s+({host}[\w\-.]+)\s""",
    """({location}\w+),({app_code}({app}LEAPS)[^,]*),TUAUDIT,({time}[^,]+),({user}[^,]+),[^,]*,\s*(?:|NULL|({dest_ip}[a-fA-F\d.:]+)|({dest_host}.+?))\s*,({object}[^,]+),[^,]*,({activity}[^,]+),([^,]*,){6}({additional_info}[^,]+),({resource}[^,]+?)\s+$""",
  ]
}
```