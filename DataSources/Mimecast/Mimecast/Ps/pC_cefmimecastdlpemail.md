#### Parser Content
```Java
{
Name = cef-mimecast-dlp-email
  Vendor = Mimecast
  Product = Mimecast
  Lms = ArcSight
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """CEF:""", """destinationServiceName =Mimecast Email Security""", """"Dir":"""", """"Sender":"""", """"Rcpt":"""" ]
  Fields = [
    """"acc":"({host}[^",]{1,2000})"""",
    """"datetime":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d[+-]\d{1,100})"""",
    """request=({outcome}[^=]{1,2000}?)\s{1,100}(\w+=|$)""",
    """suser=(<>|(({user_email}[^\s@]{1,2000}@[^\s@]{1,2000})|({user}[^\s]{1,2000})))""",
    """"Rcpt":"({recipients}({recipient}[^\s@;,"]{1,2000}@[^\s@;,"]{1,2000})[^"]{0,2000})"""",
    """"Subject":"(|({subject}[^"]{1,2000}))""""
    """requestMethod=({direction}[^=]{0,2000}?)\s{1,100}(\w+=|$)""",
    """"Dir":"({direction}[^"]{1,2000}?)""""
    """"IP":"({src_ip}[A-Fa-f\d:.]{1,2000})"""",
    """"aCode":"(|({alert_id}[^"]{1,2000}?))"""",
    """"Rcpt":"({external_address}[^\s@;,]{1,2000}@[^\s@;,"]{1,2000})""",
    """Dir=Inbound[^\}]{1,2000}?"Sender":"(<>|({external_address}[^\s@;,]{1,2000}@[^\s@;,"]{1,2000}))"""", 
    """"Sender":"(<>|({sender}[^"]{1,2000}))""""
  ]


}
```