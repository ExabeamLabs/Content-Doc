#### Parser Content
```Java
{
Name = ovirt-app-activity-38
  Vendor = oVirt
  Product = oVirt
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """EVENT_ID: NETWORK_UPDATE_VM_INTERFACE""", """ovirt""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d),.+?ovirt""",
    """EVENT_ID:\s{0,100}({activity}[^\(\)]{1,2000})""",
    """EVENT_ID:.*?Interface nic1 \(({resource}[^\)]{1,2000})\) was updated for VM ({object}[^\s"]{1,2000}?)\.\s{1,100}\(User: ({user}[^\s\(\)"]{1,2000})""",
    """({app}ovirt)"""
  ]
}
```