#### Parser Content
```Java
{
Name = vmware-failed-auth
  Vendor = VMware
  Product = VMware Horizon
  Lms = Direct
  DataType = "authentication-failed"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """ View """, """failed to authenticate because of a bad username or password""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\w+\s+\d+\s+\d+:\d+:\d+\s+({host}[\w\-.]+)\s+View""",
    """User (?:({domain}[^\\\s]+)\\+)?({user}[^\\\s]+)""",
   ]
}
```