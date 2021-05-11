#### Parser Content
```Java
{
Name = leap-app-activity
  Vendor = LEAP
  Product = LEAP
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyyMMdd:HH.mm.ss"
  Conditions = [ """|LEAPACCESS|""" ]
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """({location}\w+)\|({app_code}({app}LEAPS)[^\|]*)\|LEAPACCESS\|({time}[^\|]+)\|({user}[^\|]+)\|({object}[^\|]+)\|\s{0,100}(?:({dest_ip}[a-fA-F\d.:]+)|({dest_host}.+?))\s{0,100}\|([^\|]*\|){2}({activity}[^\|]+)\|([^\|]*\|){4}(|({additional_info}.*?))\s{1,100}$""",
  ]
}
```