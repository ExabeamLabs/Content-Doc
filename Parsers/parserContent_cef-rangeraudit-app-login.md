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
    """\[({host}[^\]]+)""",
    """epoch=({time}\d+)""",
    """requestId=({src_ip}[A-Fa-f:\d.]+)""",
    """loginId=({user}[^\s,]+)""",
    """({app}ranger)""",
  ]
}
```