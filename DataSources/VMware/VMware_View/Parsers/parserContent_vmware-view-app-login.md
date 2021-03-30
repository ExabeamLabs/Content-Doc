#### Parser Content
```Java
{
Name = vmware-view-app-login
  Vendor = VMware
  Product = VMware View
  Lms = Splunk
  DataType = "app-login"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """View User""", """ has logged in""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\d\d:\d\d:\d\d\s+({host}[^\s]+)\s+View User""",
    """View User\s+(({domain}[^\\\s]+)\\+)?({user}[^\s]+)""",
    """({app}View)"""
   ]
}
```