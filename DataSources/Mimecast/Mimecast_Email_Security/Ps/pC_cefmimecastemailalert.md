#### Parser Content
```Java
{
Name = cef-mimecast-email-alert
  Vendor = Mimecast
  Product = Mimecast Email Security
  Lms = Direct
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """dproc=TTP URL Logs""", """destinationServiceName=Mimecast Email Security""", """"userEmailAddress":"""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)\s{0,100}[^\s]{1,2000}\s{0,100}Skyformation""",
    """"date":"({time}[^"]{1,2000})""",
    """"userEmailAddress":"({user_email}[^\s@"]{1,2000}@[^\s@"]{1,2000})""",
    """"action":"({action}[^"]{1,2000})""",
    """"category":"(Unknown|({category}[^"]{1,2000}))""",
    """"{1,20}fromUserEmailAddress"{1,20}:"{1,20}({sender}[^"]{1,2000})""",
    """"{1,20}url"{1,20}:"{1,20}({url}[^"]{1,2000})""",
    """"{1,20}ttpDefinition"{1,20}:"{1,20}({service}[^"]{1,2000})""",
    """"{1,20}subject"{1,20}:"{1,20}\s{0,100}({subject}.+?)\s{0,100}"{1,20}""",
    """"{1,20}route"{1,20}:"{1,20}({direction}[^"]{1,2000})""",
    """"{1,20}scanResult"{1,20}:"{1,20}({url_verdict}[^"]{1,2000})""",
    """"{1,20}scanResult"{1,20}:"{1,20}(clean|({failure_reason}[^"]{1,2000}))"""
    ]
    DupFields = ["user_email->recipient","user_email->email_user"]
}
```