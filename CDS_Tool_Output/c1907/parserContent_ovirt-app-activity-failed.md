#### Parser Content
```Java
{
Name = ovirt-app-activity-failed
  Vendor = oVirt
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ failed for user """, """ovirt""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d),.+?ovirt""",
    """Validation of action '({activity}[^']+)""",
    """failed for user ({user}[^\s\(\)]+?)\.?\sReasons:""",
    """Reasons:\s*({failure_reason}[^"]+?)\s*$""",
    """({app}ovirt)"""
  ]
}
```