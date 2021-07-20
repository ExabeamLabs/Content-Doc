#### Parser Content
```Java
{
Name = ovirt-app-activity-16
  Vendor = oVirt
  Product = oVirt
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """EVENT_ID: NETWORK_ADD_VM_INTERFACE""", """ovirt""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d),.+?ovirt""",
    """EVENT_ID:\s{0,100}({activity}[^\(\)]{1,2000})""",
    """EVENT_ID:.*? was added to VM ({object}[^\s"]{1,2000}?)\.?\s\(User: ({user}[^\s\(\)"]{1,2000}?)(\)|\s|\.\s|\.$)""",
    """({app}ovirt)"""
  ]
}
```