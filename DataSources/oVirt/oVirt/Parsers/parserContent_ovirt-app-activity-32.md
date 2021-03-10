#### Parser Content
```Java
{
Name = ovirt-app-activity-32
  Vendor = oVirt
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """EVENT_ID: USER_FINISHED_REMOVE_DISK_ATTACHED_TO_VMS""", """ovirt""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d),.+?ovirt""",
    """EVENT_ID:\s*({activity}[^\(\)]+)""",
    """EVENT_ID:.*? Disk ({object}[^\s"]+).*? was successfully removed from domain ({resource}[^\s]+) \(User ({user}[^\s\(\)]+)""",
    """({app}ovirt)"""
  ]
}
```