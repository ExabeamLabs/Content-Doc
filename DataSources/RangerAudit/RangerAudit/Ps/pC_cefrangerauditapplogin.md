#### Parser Content
```Java
{
Name = cef-rangeraudit-app-login
  Vendor = RangerAudit
  Product = RangerAudit
  Lms = ArcSight
  DataType = "app-login"
  TimeFormat = "epoch"
  Conditions = [ """ranger""", """Login Success:""", """requestId=""" ]
  Fields = [
    """\[({host}[^\]]{1,2000})""",
    """epoch=({time}\d{1,100})""",
    """requestId=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """loginId=({user}[^\s,]{1,2000})""",
    """({app}ranger)""",
  ]
}
```