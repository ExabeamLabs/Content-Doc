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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d),.+?ovirt""",
    """EVENT_ID:\s{0,100}({activity}[^\(\)]{1,2000})""",
    """EVENT_ID:.*?User(:)? ({user}[^\s\(\)"]{1,2000}?)(\)|\s|\.\s|\.$)""",
    """EVENT_ID:.*? Storage Domain ({object}[^\s"]{1,2000}) was detached from Data Center Exabeam by ({user}[^\s\(\)]{1,2000}?)(\)|\s|\.\s|\.$)""",
    """({app}ovirt)"""
  ]
}
```