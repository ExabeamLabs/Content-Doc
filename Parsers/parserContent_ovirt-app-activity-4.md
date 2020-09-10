#### Parser Content
```Java
{
Name = ovirt-app-activity-4
  Vendor = oVirt
  Product = oVirt
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """EVENT_ID: VM_CONSOLE_DISCONNECTED""", """ovirt""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d),.+?ovirt""",
    """EVENT_ID:\s*({activity}[^\(\)]+)""",
    """EVENT_ID:.*?User ({user}[^\s\(\)"]+) got disconnected from VM ({object}[^\s"]+)""",
    """({app}ovirt)"""
  ]
}
```