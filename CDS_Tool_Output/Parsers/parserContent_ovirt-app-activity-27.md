#### Parser Content
```Java
{
Name = ovirt-app-activity-27
  Vendor = oVirt
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """EVENT_ID: USER_UPDATE_CLUSTER""", """ovirt""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d),.+?ovirt""",
    """EVENT_ID:\s*({activity}[^\(\)]+)""",
    """EVENT_ID:.*? Host cluster ({object}[^\s"]+) was updated by ({user}[^\s\(\)]+?)(\)|\s|\.\s|\.$)""",
    """({app}ovirt)"""
  ]
}
```