#### Parser Content
```Java
{
Name = cef-mimecast-email-alert-2
  Vendor = Mimecast
  Product = Email Security
  Lms = Direct
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """destinationServiceName =Mimecast Email Security""", """"sender":"""", """"recipient":"""", """"msgid":"""", """"reason":"""", """"urlCategory":"""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S{1,2000})""",
    """"datetime":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d[+-]\d{1,100})"""",
    """"sender":"({sender}[^@"]{1,2000}@[^\."]{1,2000}\.[^"]{1,2000})"""",
    """"recipient":"({recipient}[^@"]{1,2000}@[^\."]{1,2000}\.[^"]{1,2000})"""",
    """"subject":"({subject}[^"]{1,2000})"""",
    """"route":"({direction}[^"]{1,2000})"""",
    """"action":"({outcome}[^"]{1,2000})"""",
    """"msgid":"<({message_id}[^"]{1,2000})>"""",
    """"sourceIp":"({src_ip}[A-Fa-f\d:.]{1,2000})"""",
    """"url":"({url}[^"]{1,2000})"""",
    """"urlCategory":"({category}[^"]{1,2000})"""",
    """"reason":"({reason}[^"]{1,2000})"""",
    """"acc":"({user}[^"]{1,2000})""""
    ]


}
```