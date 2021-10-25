#### Parser Content
```Java
{
Name = ovirt-app-activity-14
  Vendor = oVirt
  Product = oVirt
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """EVENT_ID: USER_INITIATED_SHUTDOWN_VM""", """ovirt""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d),.+?ovirt""",
    """EVENT_ID:\s{0,100}({activity}[^\(\)]{1,2000})""",
    """EVENT_ID:.*? VM shutdown initiated by ({user}[^\s\(\)]{1,2000}) on VM ({object}[^\s"]{1,2000}) \(Host: ({resource}[^\)]{1,2000})""",
    """({app}ovirt)"""
  ]
}
```