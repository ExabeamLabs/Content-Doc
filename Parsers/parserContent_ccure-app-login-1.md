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
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """"messageutc":"({time}[^"]+)""",
    """"statecode":"({event_name}[^"]+)""",
    """"primaryobjectname":"*(null|({last_name}[^",]+?)\s*,\s*({first_name}[^",]+?))\s*"""",
    """<ApplicationName[^>]*>({app}[^<"]+)<\/ApplicationName>""",
  ]
}
```