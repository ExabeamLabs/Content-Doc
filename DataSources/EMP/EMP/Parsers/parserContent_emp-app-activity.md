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
    """EMP-LOGS ([^\|]{0,2000}\|)({location}[^\|]{1,2000})\|({app}[^\|]{1,2000})\|({host}[^\|]{1,2000})\|[^\|]{0,2000}\|({user}[^\s\|]{1,2000})\|({activity}[^\|]{1,2000})\|({time}[^\|]{1,2000})\|(null|({object}[^\|]{1,2000}))\|(null|({additional_info}[^\|]{1,2000}))\|""",
  ]
  DupFields = [ "app->app_code" ]
}
```