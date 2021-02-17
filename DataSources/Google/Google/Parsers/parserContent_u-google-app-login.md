#### Parser Content
```Java
{
Name = u-google-app-login
  Vendor = Google
  Product = Google
  Lms = Sumo
  DataType = "app-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"applicationName":""", """"token"""", """"uniqueQualifier":""",  """"authorize"""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}[^\s]+)""",
    """"time"\s*:\s*"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """"profileId"\s*:\s*"({user_id}\d+)""",
    """"actor"\s*:\s*\{.*?"email"\s*:\s*"({user_email}({user}[^@"]+)@[^"]+)"""",
    """"name"\s*:\s*"client_id",\s*"value"\s*:\s*"({account}[^"]+)"""",
    """"name"\s*:\s*"app_name",\s*"value"\s*:\s*"({app}[^"]+)"""",
  ]
}
```