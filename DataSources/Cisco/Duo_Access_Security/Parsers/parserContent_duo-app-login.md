#### Parser Content
```Java
{
Name = duo-app-login
  Vendor = Cisco
  Product = Duo Access Security
  Lms = Direct
  DataType = "app-login"
  TimeFormat = "epoch_sec"
  Conditions = [ ""","SUCCESS","""" ]
  Fields = [
    """exabeam_raw=.*?"({time}\d{10})"""",
    """exabeam_host=({host}[^\s]+)""",
    """SUCCESS","({user}[^"]+)"""",
    """"\d{10}",(("[^"]+")?,)"(?:n\/a|({auth_method}[^"]+))"""",
    """"\d{10}",(("[^"]+")?,){2}"({app}[^"]+)"""",
    """"\d{10}",(("[^"]+")?,){3}"(?:0\.0\.0\.0|({src_ip}[^"]+))"""" 
  ]
}
```