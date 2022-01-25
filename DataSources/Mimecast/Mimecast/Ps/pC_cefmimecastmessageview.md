#### Parser Content
```Java
{
Name = cef-mimecast-message-view
  Vendor = Mimecast
  Product = Mimecast
  Lms = ArcSight
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """CEF:""", """destinationServiceName =Mimecast Email Security""", """"viewer":"""", """"discoveryCase":""", """"contentViewed":"""]
  Fields = [
    """"viewed":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d[+-]\d{1,100})"""",
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """"viewer":"({user_email}[^"]{1,2000}?)"""",
    """({app}Mimecast Email Security)""",
    """({activity}Archive Message View Logs)""",
    """"subject":"({object}[^"]{1,2000}?)"""",
    """"to":"({target}[^"]{1,2000}?)"""",
    """"from":"({log_source}[^"]{1,2000}?)"""",
    """"({result}discoveryCase":\w+)""" 
    """"source":"({resource}[^"]{1,2000}?)"""",
    """"({additional_info}contentViewed[^}]{1,2000}?\})"""
  ]


}
```