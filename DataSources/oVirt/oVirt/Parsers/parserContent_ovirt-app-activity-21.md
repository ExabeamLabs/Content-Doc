#### Parser Content
```Java
{
Name = ovirt-app-activity-21
  Vendor = oVirt
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """EVENT_ID: USER_IMPORT_IMAGE_AS_TEMPLATE_FINISHED_SUCCESS""", """ovirt""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d),.+?ovirt""",
    """EVENT_ID:\s*({activity}[^\(\)]+)""",
    """EVENT_ID:.*?User ({user}[^\s\(\)"]+)""",
    """({app}ovirt)"""
  ]
}
```