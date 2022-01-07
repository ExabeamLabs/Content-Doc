#### Parser Content
```Java
{
Name = cef-google-app-login-1
  Vendor = Google
  Product = Workspace
  Lms = ArcSight
  DataType = "app-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """destinationServiceName =Google Apps""", """|login-success|""", """cs6=""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?(::ffff:)?({host}[^\s]{1,2000})""",
    """"time"\s{0,100}:\s{0,100}"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """"ipAddress"\s{0,100}:\s{0,100}"({src_ip}[\da-fA-F\.:]{1,2000})"""",
    """({activity}login-success)""",
    """({event_name}login_success)""",
    """"profileId"\s{0,100}:\s{0,100}"({user_id}\d{1,100})""",
    """"actor"\s{0,100}:\s{0,100}\{[^\}]{0,2000}?"email"\s{0,100}:\s{0,100}"({user_email}({user}[^@"]{1,2000})@[^"]{1,2000})"""",
    """"events"[\\n\s]{0,100}:[^\]]{0,2000}?"name"[\\n\s]{0,100}:[\\n\s]{0,100}"login_type"[\\n\s]{0,100

}
```