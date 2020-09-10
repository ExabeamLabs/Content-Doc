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
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d),.+?ovirt""",
    """EVENT_ID:\s*({activity}[^\(\)]+)""",
    """EVENT_ID:.*?Interface nic1 \(({resource}[^\)]+)\) was updated for VM ({object}[^\s"]+?)\.\s+\(User: ({user}[^\s\(\)"]+)""",
    """({app}ovirt)"""
  ]
}
```