#### Parser Content
```Java
{
Name = osirium-app-login
  Vendor = Osirium
  Lms = Direct
  DataType = "app-login"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """:User u'""", """ logged """ ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=([^=]+@\s*)?({host}[\w\-.]+)""",
    """:User u\'({user}[^\s\']+)""",
    """address\s*\'({src_ip}[a-fA-F:\d.]+)\'\s*logged""",
    """({app}osirium)"""
  ]
}
```