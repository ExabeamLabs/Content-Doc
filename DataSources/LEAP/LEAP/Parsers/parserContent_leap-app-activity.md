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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """({location}\w+)\|({app_code}({app}LEAPS)[^\|]{0,2000})\|LEAPACCESS\|({time}[^\|]{1,2000})\|({user}[^\|]{1,2000})\|({object}[^\|]{1,2000})\|\s{0,100}(?:({dest_ip}[a-fA-F\d.:]{1,2000})|({dest_host}.+?))\s{0,100}\|([^\|]{0,2000}\|){2}({activity}[^\|]{1,2000})\|([^\|]{0,2000}\|){4}(|({additional_info}.*?))\s{1,100}$""",
  ]
}
```