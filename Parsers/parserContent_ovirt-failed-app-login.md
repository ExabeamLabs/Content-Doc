#### Parser Content
```Java
{
Name = ovirt-failed-app-login
  Vendor = oVirt
  Lms = Direct
  DataType = "failed-app-login"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """EVENT_ID: USER_VDC_LOGIN_FAILED""", """ovirt""", """failed to log in""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d),.+?ovirt""",
    """USER_VDC_LOGIN_FAILED.+? User ({user}[^\s]+) connecting from '({src_ip}[A-Fa-f:\d.]+)""",
    """({app}ovirt)"""
  ]
}
```