#### Parser Content
```Java
{
Name = cef-rangeraudit-failed-login
  Vendor = RangerAudit 
  Lms = ArcSight
  DataType = "failed-app-login"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ranger""", """Login Unsuccessful:""", """Ip Address:""" ]
  Fields = [
    """\[({host}[^\]]+)""",
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """Ip Address:({src_ip}[A-Fa-f:\d.]+)\s*\|\s*({failure_reason}.+?)\s*$""",
    """({app}ranger)""",
  ]
}
```