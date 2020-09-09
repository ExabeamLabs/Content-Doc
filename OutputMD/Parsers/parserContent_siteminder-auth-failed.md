#### Parser Content
```Java
{
Name = siteminder-auth-failed
  Vendor = SiteMinder
  Lms = Direct
  DataType = "authentication-failed"
  TimeFormat = "dd/MMM/yyyy:HH:mm:ss Z"
  Conditions = [ """AuthAttempt """, """ [""", """] """" ]
  Fields = [
    """({outcome}AuthAttempt) ({host}[\w\-.]+) \[({time}\d+\/\w+\/\d\d\d\d:\d\d:\d\d:\d\d [+-]\d+)\] "({src_ip}[A-Fa-f:\d.]+) ({user}[^\s,]+)" "({app}.+?) \S+ ({resource}[^"\s]+)""""
  ]
}
```