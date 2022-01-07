#### Parser Content
```Java
{
Name = cef-google-password-update
  Vendor = Google
  Product = Workspace
  Lms = ArcSight
  DataType = "password-change"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [  """"CHANGE_PASSWORD"""", """destinationServiceName =Google Apps""", """"USER_SETTINGS"""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """"time"\s{0,10}:\s{0,10}"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)"""",
    """({event_name}CHANGE_PASSWORD)""",
    """"ipAddress"\s{0,10}:\s{0,10}"({src_ip}[a-fA-F:\d.]{1,2000}?)"""",
    """"email"\s{0,10}:\s{0,10}"({user_email}[^"@]{1,2000}?@[^"]{1,2000}?)"""",
    """"name"\s{0,10}:\s{0,10}"USER_EMAIL"[^"]{0,10}"value"\s{0,10}:\s{0,10}"({target_user}[^"@]{1,2000}@[^"]{1,2000})"""", 
    """destinationServiceName =({app}[^=]{1,2000}?)\s{0,10}(\w{1,2000}=|$)"""    
  ]


}
```