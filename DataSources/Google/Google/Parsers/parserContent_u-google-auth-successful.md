#### Parser Content
```Java
{
Name = u-google-auth-successful
  Vendor = Google
  Product = Google
  Lms = Sumo
  DataType = "app-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"applicationName":""", """"login"""", """"uniqueQualifier":""",  """"login_success"""" ]
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}[^\s]+)""",
    """"time"\s{0,100}:\s{0,100}"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """"ipAddress"\s{0,100}:\s{0,100}"({src_ip}[\da-fA-F\.:]+)""",
    """"profileId"\s{0,100}:\s{0,100}"({user_id}\d{1,100})""",
    """"actor"\s{0,100}:\s{0,100}\{.*?"email"\s{0,100}:\s{0,100}"({user_email}({user}[^@"]+)@[^"]+)"""",
    """"events"\s{0,100}:.*?"name"\s{0,100}:\s{0,100}"login_type"\s{0,100}
```