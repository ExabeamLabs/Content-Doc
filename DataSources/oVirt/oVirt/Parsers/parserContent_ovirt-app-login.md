#### Parser Content
```Java
{
Name = ovirt-app-login
  Vendor = oVirt
  Product = oVirt
  Lms = Direct
  DataType = "app-login"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """EVENT_ID: USER_VDC_LOGIN""", """ovirt""", """logged in""" ]
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d),.+?ovirt""",
    """USER_VDC_LOGIN.+? User (?:({user_email}[^\s@]+@({email_domain}[^\s@]+))\S*|({user}[^\s]+)) connecting from '({src_ip}[A-Fa-f:\d.]+)""",
    """({app}ovirt)"""
  ]
}
```