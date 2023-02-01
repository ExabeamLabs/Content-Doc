#### Parser Content
```Java
{
Name = adminbyrequest-privileged-access
  Vendor = Admin By Request
  Product = Admin By Request
  Lms = Direct
  DataType = "privileged-access"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """"type":"Admin Session"""" , """"elevatedApplications":""", """"approvedBy":""", """"traceNo":"""" ]
  Fields = [
    """"requestTime":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)"""",
    """"user":[^=]{1,2000}?"account":"(({domain}[^\\]{1,2000})\\+)?({user}[^"]{1,2000})""",
    """"user":[^=]{1,2000}?"email":"({user_email}[^@"]{1,2000}@[^\."]{1,2000}\.[^"]{1,2000})""",
    """"user":[^=]{1,2000}?"fullName":"({user_fullname}[^"]{1,2000})""",
    """"computer":[^=]{1,2000}?"name":"({host}[^"]{1,2000})""",
    """"computer":[^=]{1,2000}?"model":"({additional_info}[^"]{1,2000}?)"""",
    """"type":"({event_name}Admin Session)"""" 
  ]


}
```