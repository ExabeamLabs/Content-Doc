#### Parser Content
```Java
{
Name = cef-mimecast-web-activity
  Vendor = Mimecast
  Product = Targeted Threat Protection - URL
  Lms = ArcSight
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = ["""CEF:""", """destinationServiceName =Mimecast Email Security""", """"action":"""", """"url":"""", """"category":""" ]
  Fields = [
    """"date":"({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100})""",
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"userEmailAddress":"({user_email}[^\s@"]{1,2000}@[^\s@"]{1,2000})""",
    """"action":"({action}[^"]{1,2000})""",
    """"category":"(Unknown|({category}[^"]{1,2000}))""",
    """"url":"(-|({full_url}(({protocol}[^:\\\/\s,"]{1,2000}):[\\\/]{1,2000})?[\\\/]{0,2000}(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({web_domain}[^\\\/\s:,"]{1,2000}))(:({dest_port}\d{1,100}))?({uri_path}\/[^\?",]{0,2000}?)?({uri_query}\?[^"]{0,2000}?)?))\s{0,100}"""",
  ]


}
```