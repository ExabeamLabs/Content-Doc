#### Parser Content
```Java
{
Name = cef-mimecast-email-alert-3
  Vendor = Mimecast
  Product = Email Security
  Lms = ArcSight
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """CEF:""", """destinationServiceName =Mimecast Email Security""", """dtz=default-tenant""", """request=""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z) ([\w.\-]{1,2000}) """,
    """"acc":"({user}[^"]{1,2000})""",
    """"aCode":"(|({alert_id}[^"]{1,2000}?))"""",
    """"Dir":"({direction}[^"]{1,2000}?)"""",
    """"Subject":"(|({subject}[^"]{1,2000}?))([\\]{1,100})?\s{0,100}"""",
    """dproc=({dproc}[^=]{1,2000})\s\w+=""",
    """request=({outcome}[^\s]{1,2000})""",
    """requestClientApplication=({user_agent}.+?)\s\w+=""",
    """suser=({sender}[^\s]{1,2000})""",
    """"Rcpt":"({recipients}({recipient}[^\s@;,"]{1,2000}@[^\s@;,"]{1,2000})[^"]{0,2000})"""",
    """"Rcpt":"({external_address}[^\s@;,]{1,2000}@[^\s@;,"]{1,2000})""" 
  ]


}
```