#### Parser Content
```Java
{
Name = u-google-auth-successful
  Vendor = Google
  Lms = Sumo
  DataType = "app-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"applicationName":""", """"login"""", """"uniqueQualifier":""",  """"login_success"""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}[^\s]+)""",
    """"time"\s*:\s*"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """"ipAddress"\s*:\s*"({src_ip}[\da-fA-F\.:]+)""",
    """"profileId"\s*:\s*"({user_id}\d+)""",
    """"actor"\s*:\s*\{.*?"email"\s*:\s*"({user_email}({user}[^@"]+)@[^"]+)"""",
    """"events"\s*:.*?"name"\s*:\s*"login_type"\s*,\s*"value"\s*:\s*"({login_type}.+?)"""",
  ]
}
```