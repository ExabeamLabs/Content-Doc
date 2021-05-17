#### Parser Content
```Java
{
Name = osirium-app-login
  Vendor = Osirium
  Product = Osirium
  Lms = Direct
  DataType = "app-login"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """:User u'""", """ logged """ ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[\w\-.]{1,2000})""",
    """:User u\'({user}[^\s\']{1,2000})""",
    """address\s{0,100}\'({src_ip}[a-fA-F:\d.]{1,2000})\'\s{0,100}logged""",
    """({app}osirium)"""
  ]
}
```