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
    """exabeam_host=([^=]+@\s{0,100})?({host}[^\s]+)""",
    """"time"\s{0,100}:\s{0,100}"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """"profileId"\s{0,100}:\s{0,100}"({user_id}\d{1,100})""",
    """"actor"\s{0,100}:\s{0,100}\{.*?"email"\s{0,100}:\s{0,100}"({user_email}({user}[^@"]+)@[^"]+)"""",
    """"name"\s{0,100}:\s{0,100}"client_id",\s{0,100}"value"\s{0,100}:\s{0,100}"({account}[^"]+)"""",
    """"name"\s{0,100}:\s{0,100}"app_name",\s{0,100}"value"\s{0,100}:\s{0,100}"({app}[^"]+)"""",
  ]
}
```