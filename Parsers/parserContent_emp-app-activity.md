#### Parser Content
```Java
{
Name = emp-app-activity
  Vendor = EMP
  Product = EMP
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """EMP-LOGS""", """|ICALL|""" ]
  Fields = [
    """EMP-LOGS ([^\|]*\|)({location}[^\|]+)\|({app}[^\|]+)\|({host}[^\|]+)\|[^\|]*\|({user}[^\s\|]+)\|({activity}[^\|]+)\|({time}[^\|]+)\|(null|({object}[^\|]+))\|(null|({additional_info}[^\|]+))\|""",
  ]
  DupFields = [ "app->app_code" ]
}
```