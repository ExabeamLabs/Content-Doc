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
    """\w+\s{1,100}\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}({host}[\w\-.]{1,2000})\s{1,100}View""",
    """User (?:({domain}[^\\\s]{1,2000})\\+)?({user}[^\\\s]{1,2000})""",
   ]
}
```