#### Parser Content
```Java
{
Name = onewelcome-authentication-successful-1
  DataType = "authentication-successful"
  Conditions = [ """"originator":"onewelcome"""", """"siemcode":"120202"""", """"authres":"SUCCESS"""", """"pepmod":"sms"""", """"peptype":"AUTH-RES"""" ]

onewelcome-authentication-event = {
    Vendor = OneWelcome
    Product = OneWelcome
    Lms = Direct
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Fields = [
      """"@timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,3}Z)""",
      """"account":"(?:-|({user_email}[^@"]{1,2000}@[^\."]{1,2000}\.[^"]{1,2000})|({user}[^"]{1,2000}))"""",
      """"clientip":"({src_ip}[a-fA-F\d:\.]{1,2000})"""",
      """"siemcode":"({event_code}\d{1,20})"""",
      """"useragent":"({user_agent}[^"]{1,2000})"""",
      """"app":"({app}[^"]{1,2000})"""",
      """"type":"({auth_type}[^"]{1,2000})"""",
      """"pepmod":"({object}[^"]{1,2000})"""",
      """"result":"({outcome}[^"]{1,2000})"""",
      """"authres":"({outcome}[^"]{1,2000})"""",
      """"action":"({event_name}[^"]{1,2000})"""",
      """"hdetail":"({event_name}[^"]{1,2000})"""",
      """"human":"({additional_info}[^"]{1,2000})"""",
    ]
    DupFields = [ "event_name->activity" 
}
```