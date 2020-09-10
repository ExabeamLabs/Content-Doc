#### Parser Content
```Java
{
Name = ovirt-app-activity-11
  Vendor = oVirt
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """EVENT_ID: USER_ADDED_DISK_PROFILE""", """ovirt""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d),.+?ovirt""",
    """EVENT_ID:\s*({activity}[^\(\)]+)""",
    """EVENT_ID:.*?Disk Profile ({object}[^\s"]+) was successfully added \(User: ({user}[^\s\(\)"]+?)(\)|\s|\.\s|\.$)""",
    """({app}ovirt)"""
  ]
}
```