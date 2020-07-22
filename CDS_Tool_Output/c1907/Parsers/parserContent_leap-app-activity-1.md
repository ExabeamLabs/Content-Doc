#### Parser Content
```Java
{
Name = leap-app-activity-1
  Vendor = LEAP
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyyMMdd:HH.mm.ss"
  Conditions = [ """|LEAPAUDIT|""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """({location}\w+)\|({app_code}({app}LEAPS)[^\|]*)\|LEAPAUDIT\|({time}\d{8}:\d\d\.\d\d\.\d\d)\|(|({user}[^\|]+))\|([^\|]*\|){2}(|({object_name}[^\|]+))\|(|({field_name}[^\|]+))\|(|({activity}[^\|]+))\|(|({additional_info}[^\|]*\|[^\|]*))\|(|({primary_key}[^\|]+))\|\s*(|({secondary_key}[^\|]+))\s*\|"""
  ]
}
```