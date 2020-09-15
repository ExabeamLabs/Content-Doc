#### Parser Content
```Java
{
Name = duo-failed-app-login
  Vendor = Duo Security
  Product = Duo Security
  Lms = Direct
  DataType = "failed-app-login"
  TimeFormat = "epoch_sec"
  Conditions = [ ""","FAILURE",""""]
  Fields = [
    """exabeam_raw=.*?"({time}\d{10})"""",
    """exabeam_host=({host}[^\s]+)""",
    """FAILURE","({user}[^"]+)"""",
    """"({failure_reason}[^"]+)","FAILURE",""",
    """"\d{10}",(("[^"]+")?,)"(?:n\/a|({auth_method}[^"]+))"""",
    """"\d{10}",(("[^"]+")?,){2}"({app}[^"]+)"""",
    """"\d{10}",(("[^"]+")?,){3}"(?:0\.0\.0\.0|({src_ip}[^"]+))"""" 
  ]
}
```