#### Parser Content
```Java
{
Name = ovirt-app-activity-27
  Vendor = oVirt
  Product = oVirt
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """EVENT_ID: USER_UPDATE_CLUSTER""", """ovirt""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d),.+?ovirt""",
    """EVENT_ID:\s{0,100}({activity}[^\(\)]{1,2000})""",
    """EVENT_ID:.*? Host cluster ({object}[^\s"]{1,2000}) was updated by ({user}[^\s\(\)]{1,2000}?)(\)|\s|\.\s|\.$)""",
    """({app}ovirt)"""
  ]
}
```