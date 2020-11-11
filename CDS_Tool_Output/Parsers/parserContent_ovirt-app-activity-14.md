#### Parser Content
```Java
{
Name = ovirt-app-activity-14
  Vendor = oVirt
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """EVENT_ID: USER_INITIATED_SHUTDOWN_VM""", """ovirt""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d),.+?ovirt""",
    """EVENT_ID:\s*({activity}[^\(\)]+)""",
    """EVENT_ID:.*? VM shutdown initiated by ({user}[^\s\(\)]+) on VM ({object}[^\s"]+) \(Host: ({resource}[^\)]+)""",
    """({app}ovirt)"""
  ]
}
```