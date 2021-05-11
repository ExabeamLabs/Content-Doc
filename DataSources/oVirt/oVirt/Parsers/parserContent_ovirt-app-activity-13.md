#### Parser Content
```Java
{
Name = ovirt-app-activity-13
  Vendor = oVirt
  Product = oVirt
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """EVENT_ID: USER_STOPPED_VM_INSTEAD_OF_SHUTDOWN""", """ovirt""" ]
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d),.+?ovirt""",
    """EVENT_ID:\s{0,100}({activity}[^\(\)]+)""",
    """EVENT_ID:.*?User(:)? ({user}[^\s\(\)"]+?)(\)|\s|\.\s|\.$)""",
    """EVENT_ID:.*? VM ({object}[^\s"]+) was powered off ungracefully by ({user}[^\s\(\)]+) \(Host: ({resource}[^\)]+)""",
    """({app}ovirt)"""
  ]
}
```