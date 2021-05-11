#### Parser Content
```Java
{
Name = ccure-app-login-1
  Vendor = Tyco
  Product = CCURE Building Management System
  Lms = Direct
  DataType = "app-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"messagetype":"""", """"statecode":"LoggedIn"""", """"primaryobjectname":"""" ]
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """"messageutc":"({time}[^"]+)""",
    """"statecode":"({event_name}[^"]+)""",
    """"primaryobjectname":"{0,20}(null|({last_name}[^",]+?)\s{0,100}
```