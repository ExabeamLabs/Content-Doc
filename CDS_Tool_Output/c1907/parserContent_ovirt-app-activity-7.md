#### Parser Content
```Java
{
Name = ovirt-app-activity-7
  Vendor = oVirt
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """EVENT_ID: USER_CHANGE_DISK_VM""", """ovirt""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d),.+?ovirt""",
    """EVENT_ID:\s*({activity}[^\(\)]+)""",
    """EVENT_ID:.*? was inserted to VM ({object}[^\s"]+) by ({user}[^\s\(\)]+?)(\)|\s|\.\s|\.$)""",
    """({app}ovirt)"""
  ]
}
```