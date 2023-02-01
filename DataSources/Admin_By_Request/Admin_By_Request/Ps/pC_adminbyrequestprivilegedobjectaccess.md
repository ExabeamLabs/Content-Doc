#### Parser Content
```Java
{
Name = adminbyrequest-privileged-object-access
  Vendor = Admin By Request
  Product = Admin By Request
  Lms = Direct
  DataType = "privileged-object-access"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """"type":"Run As Admin"""" , """"elevatedApplications":""", """"approvedBy":""", """"traceNo":"""" ]
  Fields = [
    """"requestTime":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)"""",
    """"user":[^=]{1,2000}?"account":"(({domain}[^\\]{1,2000})\\+)?({user}[^"]{1,2000})""",
    """"user":[^=]{1,2000}?"email":"({user_email}[^@"]{1,2000}@[^\."]{1,2000}\.[^"]{1,2000})""",
    """"user":[^=]{1,2000}?"fullName":"({user_fullname}[^"]{1,2000})""",
    """"computer":[^=]{1,2000}?"name":"({host}[^"]{1,2000})""",
    """"computer":[^=]{1,2000}?"model":"({additional_info}[^"]{1,2000}?)"""",
    """"type":"({event_name}Run As Admin)"""",
    """"application":\{[^=]{0,2000}?"file":"({object}[^"]{1,2000})""",
    """"elevatedApplications":\[\{[^=]{1,2000}?"file":"({object}[^"]{1,2000})"""
  ]


}
```