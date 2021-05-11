#### Parser Content
```Java
{
Name = siteminder-auth-failed
  Vendor = SiteMinder
  Product = SiteMinder
  Lms = Direct
  DataType = "authentication-failed"
  TimeFormat = "dd/MMM/yyyy:HH:mm:ss Z"
  Conditions = [ """AuthAttempt """, """ [""", """] """" ]
  Fields = [
    """({outcome}AuthAttempt) ({host}[\w\-.]+) \[({time}\d{1,100}\/\w+\/\d\d\d\d:\d\d:\d\d:\d\d [+-]\d{1,100})\] "({src_ip}[A-Fa-f:\d.]+) ({user}[^\s,]+)" "({app}.+?) \S+ ({resource}[^"\s]+)""""
  ]
}
```