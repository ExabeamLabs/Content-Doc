#### Parser Content
```Java
{
Name = netskope-app-activity-1
  Vendor = Netskope
  Product = Security Cloud
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """"event-name":"resource-property-updated"""", """"audit_log_event":""", """"triggered-by":""", """"src-application-name":"Netskope"""" ]
  Fields = [
    """"time":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)"""",
    """"user":"(unknown|({user_email}[^@"]{1,2000}@[^\."]{1,2000}\.[^"]{1,2000}))""",
    """"audit_log_event":"({event_name}[^"]{1,2000})""",
    """"({activity}resource-property-updated)"""",
    """"({app}Netskope)"""",
    """"identifier":\{({additional_info}[^\}]{1,2000}?"name":"({object}[^"]{1,2000})")\}"""
  ]


}
```