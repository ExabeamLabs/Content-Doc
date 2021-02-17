#### Parser Content
```Java
{
Name = vmware-view-remote-logon-1
  Vendor = VMware
  Product = VMware View
  Lms = Splunk
  DataType = "remote-logon"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """View User""", """has logged in to a new session on machine""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\d\d:\d\d:\d\d\s+({host}[^\s]+)\s+View User""",
    """View User\s+(({domain}[^\\\s]+)\\+)?({user}[^\s]+)""",
    """({app}View)""",
    """new session on machine\s+({dest_host}[\w.-]+)"""
   ]
}
```