#### Parser Content
```Java
{
Name = cef-rangeraudit-failed-login
  Vendor = RangerAudit
  Product = RangerAudit
  Lms = ArcSight
  DataType = "failed-app-login"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ranger""", """Login Unsuccessful:""", """Ip Address:""" ]
  Fields = [
    """\[({host}[^\]]{1,2000})""",
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """Ip Address:({src_ip}[A-Fa-f:\d.]{1,2000})\s{0,100}\|\s{0,100}({failure_reason}.+?)\s{0,100}$""",
    """({app}ranger)""",
  ]
}
```