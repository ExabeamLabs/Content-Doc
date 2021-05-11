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
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d),.+?ovirt""",
    """EVENT_ID:\s{0,100}({activity}[^\(\)]+)""",
    """EVENT_ID:.*? was added to VM ({object}[^\s"]+?)\.?\s\(User: ({user}[^\s\(\)"]+?)(\)|\s|\.\s|\.$)""",
    """({app}ovirt)"""
  ]
}
```