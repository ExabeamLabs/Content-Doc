#### Parser Content
```Java
{
Name = netskope-login-1
  Vendor = Netskope
  Product = Security Cloud
  Lms = Direct
  DataType = "app-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """"audit_log_event":"Login Successful"""" , """"type":"""", """"event-name":"login-success"""", """"src-application-name":"Netskope"""" ]
  Fields = [
    """"time":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)"""",
    """"user":"(unknown|({user_email}[^@"]{1,2000}@[^\."]{1,2000}\.[^"]{1,2000}))""",
    """"audit_log_event":"({event_name}[^"]{1,2000})""",
    """"({activity}login-success)"""",
    """"src-ip":"({src_ip}[a-fA-F\d:\.]{1,2000})"""",
    """"({app}Netskope)""""
  ]


}
```