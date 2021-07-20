#### Parser Content
```Java
{
Name = leap-app-activity-1
  Vendor = LEAP
  Product = LEAP
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyyMMdd:HH.mm.ss"
  Conditions = [ """|LEAPAUDIT|""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """({location}\w+)\|({app_code}({app}LEAPS)[^\|]{0,2000})\|LEAPAUDIT\|({time}\d{8}:\d\d\.\d\d\.\d\d)\|(|({user}[^\|]{1,2000}))\|([^\|]{0,2000}\|){2}(|({object_name}[^\|]{1,2000}))\|(|({field_name}[^\|]{1,2000}))\|(|({activity}[^\|]{1,2000}))\|(|({additional_info}[^\|]{0,2000}\|[^\|]{0,2000}))\|(|({primary_key}[^\|]{1,2000}))\|\s{0,100}(|({secondary_key}[^\|]{1,2000}))\s{0,100}\|"""
  ]
}
```