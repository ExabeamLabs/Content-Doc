#### Parser Content
```Java
{
Name = code42-app-activity
  Vendor = Code42
  Product = Code42 Incydr
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions= [ """"actorType": "API_CLIENT"""", """"actorName"""", """"success":""", """Code42""" ]
  Fields = [
    """timestamp":\s{0,100}"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z)"""",
    """destinationServiceName =({app}Custom Application)""",
    """"actorName":\s{0,100}"({user}[^"\s]{1,2000})""",
    """"audit_log:+({activity}[^"]{1,2000})""",
    """"actorIpAddress":\s{0,100}"({src_ip}[A-Fa-f\d.:]{1,2000})"""",
  ]


}
```