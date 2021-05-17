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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d),.+?ovirt""",
    """EVENT_ID:\s{0,100}({activity}[^\(\)]{1,2000})""",
    """EVENT_ID:.*?User(:)? ({user}[^\s\(\)"]{1,2000}?)(\)|\s|\.\s|\.$)""",
    """EVENT_ID:.*? VM ({object}[^\s"]{1,2000}) was powered off ungracefully by ({user}[^\s\(\)]{1,2000}) \(Host: ({resource}[^\)]{1,2000})""",
    """({app}ovirt)"""
  ]
}
```