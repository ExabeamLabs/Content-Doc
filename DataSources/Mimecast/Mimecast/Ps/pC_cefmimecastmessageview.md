#### Parser Content
```Java
{
Name = cef-mimecast-message-view
  Vendor = Mimecast
  Product = Mimecast
  Lms = ArcSight
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """CEF:""", """|SkyFormation Cloud Apps Security|""", """destinationServiceName =Mimecast Email Security dproc=Archive Message View Logs""", """"viewer":"""", """"discoveryCase":""", """"contentViewed":"""]
  Fields = [
    """({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}\.\d{1,100}Z)\s{1,100}[\w\-.]{1,2000}\s{1,100}Skyformation""",
    """"viewer":"({user_email}[^"]{1,2000}?)"""",
    """({app}Mimecast Email Security)""",
    """({activity}Archive Message View Logs)""",
    """"subject":"({object}[^"]{1,2000}?)"""",
    """"to":"({target}[^"]{1,2000}?)"""",
    """"from":"({log_source}[^"]{1,2000}?)"""",
    """"({result}discoveryCase":\w+)""" 
    """"source":"({resource}[^"]{1,2000}?)"""",
    """"({additional_info}contentViewed.+?\})"""
  ]


}
```