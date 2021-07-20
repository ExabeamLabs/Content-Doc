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
    """\d\d:\d\d:\d\d\s{1,100}({host}[^\s]{1,2000})\s{1,100}View User""",
    """View User\s{1,100}(({domain}[^\\\s]{1,2000})\\+)?({user}[^\s]{1,2000})""",
    """({app}View)""",
    """new session on machine\s{1,100}({dest_host}[\w.-]{1,2000})"""
   ]
}
```