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
    """exabeam_host=({host}[^\s]{1,2000})""",
    """SUCCESS","({user}[^"]{1,2000})"""",
    """"\d{10}",(("[^"]{1,2000}")?,)"(?:n\/a|({auth_method}[^"]{1,2000}))"""",
    """"\d{10}",(("[^"]{1,2000}")?,){2}"({app}[^"]{1,2000})"""",
    """"\d{10}",(("[^"]{1,2000}")?,){3}"(?:0\.0\.0\.0|({src_ip}[^"]{1,2000}))"""" 
  ]
}
```