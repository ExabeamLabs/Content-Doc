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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d),.+?ovirt""",
    """USER_VDC_LOGIN.+? User (?:({user_email}[^\s@]{1,2000}@({email_domain}[^\s@]{1,2000}))\S*|({user}[^\s]{1,2000})) connecting from '({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """({app}ovirt)"""
  ]
}
```