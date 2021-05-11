#### Parser Content
```Java
{
Name = ovirt-app-activity-35
  Vendor = oVirt
  Product = oVirt
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """EVENT_ID: USER_DETACH_STORAGE_DOMAIN_FROM_POOL""", """ovirt""" ]
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d),.+?ovirt""",
    """EVENT_ID:\s{0,100}({activity}[^\(\)]+)""",
    """EVENT_ID:.*?User(:)? ({user}[^\s\(\)"]+?)(\)|\s|\.\s|\.$)""",
    """EVENT_ID:.*? Storage Domain ({object}[^\s"]+) was detached from Data Center Exabeam by ({user}[^\s\(\)]+?)(\)|\s|\.\s|\.$)""",
    """({app}ovirt)"""
  ]
}
```