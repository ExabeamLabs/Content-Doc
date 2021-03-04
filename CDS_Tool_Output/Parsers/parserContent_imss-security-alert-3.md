#### Parser Content
```Java
{
Name = imss-security-alert-3
  Conditions = [ """詐称メールフィルタ""" ]
}

{
  Name = leap-app-activity
  Vendor = LEAP
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyyMMdd:HH.mm.ss"
  Conditions = [ """|LEAPACCESS|""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """({location}\w+)\|({app_code}({app}LEAPS)[^\|]*)\|LEAPACCESS\|({time}[^\|]+)\|({user}[^\|]+)\|({object}[^\|]+)\|\s*(?:({dest_ip}[a-fA-F\d.:]+)|({dest_host}.+?))\s*\|([^\|]*\|){2}({activity}[^\|]+)\|([^\|]*\|){4}(|({additional_info}.*?))\s+$""",
  ]
}
```