#### Parser Content
```Java
{
Name = ovirt-app-activity-1
  Vendor = oVirt
  Product = oVirt
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """EVENT_ID: VM_SET_TICKET""", """ovirt""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d),.+?ovirt""",
    """EVENT_ID:\s{0,100}({activity}[^\(\)]{1,2000})""",
    """EVENT_ID:.*?User ({user}[^\s\(\)"]{1,2000}) initiated console session for VM ({object}[^\s"]{1,2000})""",
    """({app}ovirt)"""
  ]
}
```