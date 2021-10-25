#### Parser Content
```Java
{
Name = ovirt-app-activity-28
  Vendor = oVirt
  Product = oVirt
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """EVENT_ID: USER_STOP_VM""", """ovirt""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d),.+?ovirt""",
    """EVENT_ID:\s{0,100}({activity}[^\(\)]{1,2000})""",
    """EVENT_ID:.*? VM ({object}[^\s"]{1,2000}) powered off by ({user}[^\s\(\)]{1,2000}?) \(({resource}[^\)]{1,2000})""",
    """({app}ovirt)"""
  ]
}
```