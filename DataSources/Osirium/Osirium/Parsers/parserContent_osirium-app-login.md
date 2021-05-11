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
    """exabeam_host=([^=]+@\s{0,100})?({host}[\w\-.]+)""",
    """:User u\'({user}[^\s\']+)""",
    """address\s{0,100}\'({src_ip}[a-fA-F:\d.]+)\'\s{0,100}logged""",
    """({app}osirium)"""
  ]
}
```