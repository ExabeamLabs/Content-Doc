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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?(::ffff:)?({host}[^\s]{1,2000})""",
    """\w{3}\s\d\d\s\d\d:\d\d:\d\d\s(::ffff:)?({host}[\w\-.]{1,2000})\s\d{1,100}\s""",
    """"time"\s{0,100}:\s{0,100}"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """"ipAddress"\s{0,100}:\s{0,100}"({src_ip}[\da-fA-F\.:]{1,2000})""",
    """"profileId"\s{0,100}:\s{0,100}"({user_id}\d{1,100})""",
    """"actor"\s{0,100}:\s{0,100}\{[^\}]{0,2000}?"email"\s{0,100}:\s{0,100}"({user_email}({user}[^@"]{1,2000})@[^"]{1,2000})"""",
    """"events"\s{0,100}:[^\]]{0,2000}?"name"\s{0,100}:\s{0,100}"login_type"\s{0,100

}
```