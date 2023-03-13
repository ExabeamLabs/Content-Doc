#### Parser Content
```Java
{
Name = cloudflare-app-activity-1
  Vendor = Cloudflare
  Product = Cloudflare Insights
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """CEF:""", """destinationServiceName =Cloudflare""", """"when":"""" ]
  Fields = [
    """"when":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d{1,7})?Z)"""",
    """destinationServiceName =({app}[^\s]{1,2000})""",
    """request=({outcome}[^\s]{1,2000})""",
    """"action":\{[^\}]{1,2000}?"type":"({activity}[^"]{1,2000})"""",
    """"ip":"({src_ip}[a-fA-F\d:\.]{1,2000})"""",
    """"actor":\{"email":"({user_email}[^@"]{1,2000}@[^\."]{1,2000}\.[^"]{1,2000})"""",
    """"result":({result}[^,]{1,2000}),""",
    """msg=({additional_info}[^"]{1,2000}?)\s\w+=""",
    """"info":"({additional_info}[^"]{1,2000})"""",
    """"account_name":"({account_name}[^"]{1,2000})"""",
    """"user_email":"({account}[^"]{1,2000})""""
  ]


}
```