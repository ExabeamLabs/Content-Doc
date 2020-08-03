#### Parser Content
```Java
{
Name = ovirt-app-activity-33
  Vendor = oVirt
  Product = oVirt
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """EVENT_ID: USER_FAILED_RUN_VM""", """ovirt""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d),.+?ovirt""",
    """EVENT_ID:\s*({activity}[^\(\)]+)""",
    """EVENT_ID:.*? Failed to run VM ({object}[^\s"]+).*?The following disks are locked: ({resource}[^\s]+?)\.\s.*?\(User: ({user}[^\s\(\)"]+)""",
    """({app}ovirt)"""
  ]
}
```