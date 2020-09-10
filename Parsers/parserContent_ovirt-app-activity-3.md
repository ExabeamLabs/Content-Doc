#### Parser Content
```Java
{
Name = ovirt-app-activity-3
  Vendor = oVirt
  Product = oVirt
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """EVENT_ID: USER_STARTED_VM""", """ovirt""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d),.+?ovirt""",
    """EVENT_ID:\s*({activity}[^\(\)]+)""",
    """EVENT_ID:.*? VM ({object}[^\s"]+) was started by ({user}[^\s\(\)]+) \(Host: ({resource}[^\)]+)""",
    """({app}ovirt)"""
  ]
}
```