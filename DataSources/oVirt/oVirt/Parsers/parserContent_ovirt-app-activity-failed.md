#### Parser Content
```Java
{
Name = ovirt-app-activity-failed
  Vendor = oVirt
  Product = oVirt
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ failed for user """, """ovirt""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d),.+?ovirt""",
    """Validation of action '({activity}[^']{1,2000})""",
    """failed for user ({user}[^\s\(\)]{1,2000}?)\.?\sReasons:""",
    """Reasons:\s{0,100}({failure_reason}[^"]{1,2000}?)\s{0,100}$""",
    """({app}ovirt)"""
  ]
}
```