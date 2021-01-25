#### Parser Content
```Java
{
Name = cef-mimecast-message-view
  Vendor = Mimecast
  Product = Mimecast
  Lms = ArcSight
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """CEF:""", """|SkyFormation Cloud Apps Security|""", """destinationServiceName=Mimecast Email Security dproc=Archive Message View Logs""", """"viewer":"""", """"discoveryCase":""", """"contentViewed":"""]
  Fields = [
    """({time}\d+-\d+-\d+T\d+:\d+:\d+\.\d+Z)\s+({host}[\w\-.]+)\s+Skyformation""",
    """"viewer":"({user_email}[^"]+?)"""",
    """({app}Mimecast Email Security)""",
    """({activity}Archive Message View Logs)""",
    """"subject":"({object}[^"]+?)"""",
    """"to":"({target}[^"]+?)"""",
    """"from":"({source}[^"]+?)"""",
    """"({result}discoveryCase":\w+)""" 
    """"source":"({resource}[^"]+?)"""",
    """"({additional_info}contentViewed.+?\})"""
  ]
}
```