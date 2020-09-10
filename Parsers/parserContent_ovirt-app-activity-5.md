#### Parser Content
```Java
{
Name = ovirt-app-activity-5
  Vendor = oVirt
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """EVENT_ID: USER_UPDATE_VM""", """ovirt""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d),.+?ovirt""",
    """EVENT_ID:\s*({activity}[^\(\)]+)""",
    """EVENT_ID:.*?VM ({object}[^\s"]+) configuration was updated by ({user}[^\s\(\)"]+?)(\)|\s|\.\s|\.$)""",
    """({app}ovirt)"""
  ]
}
```