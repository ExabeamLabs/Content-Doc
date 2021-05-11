#### Parser Content
```Java
{
Name = ovirt-failed-app-login-1
  Vendor = oVirt
  Product = oVirt
  Lms = Direct
  DataType = "failed-app-login"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """Unable to log in.""", """ovirt""" ]
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d),.+?ovirt""",
    """Cannot authenticate user '({user}[^\s']+)' connecting from '({src_ip}[A-Fa-f:\d.]+)""",
    """({app}ovirt)"""
  ]
}
```