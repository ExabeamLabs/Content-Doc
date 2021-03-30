#### Parser Content
```Java
{
Name = ovirt-app-activity-31
  Vendor = oVirt
  Product = oVirt
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """EVENT_ID: USER_REMOVE_STORAGE_DOMAIN""", """ovirt""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d),.+?ovirt""",
    """EVENT_ID:\s*({activity}[^\(\)]+)""",
    """EVENT_ID:.*? Storage Domain ({object}[^\s"]+) was removed by ({user}[^\s\(\)]+?)(\)|\s|\.\s|\.$)""",
    """({app}ovirt)"""
  ]
}
```