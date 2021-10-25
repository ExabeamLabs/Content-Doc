#### Parser Content
```Java
{
Name = ovirt-app-activity-37
  Vendor = oVirt
  Product = oVirt
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """EVENT_ID: USER_ADD_VDS""", """ovirt""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d),.+?ovirt""",
    """EVENT_ID:\s{0,100}({activity}[^\(\)]{1,2000})""",
    """EVENT_ID:.*? Host ({object}[^\s"]{1,2000}) was added by ({user}[^\s\(\)]{1,2000}?)(\)|\s|\.\s|\.$)""",
    """({app}ovirt)"""
  ]
}
```