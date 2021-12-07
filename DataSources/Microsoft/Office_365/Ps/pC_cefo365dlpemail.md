#### Parser Content
```Java
{
Name = cef-o365-dlp-email
  Vendor = Microsoft
  Product = Office 365
  Lms = ArcSight
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """CEF:""", """=Office 365""", """"MessageTraceId":"""", """"EventType":"""", """"RecipientAddress":"""", """"SenderAddress":"""", """"Direction":"""", """"Subject":""""]

  Fields = [
    """exabeam_host=([^=]{1,2000}?@\s{0,100})?({host}[\w.-]{1,2000})""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)\.\d{1,100}Z\s{1,100}[\w\-.]{1,2000}\s{1,100}"""
    """filePath=<*({file_path}.+?)>*\s\w+=""",
    """fname=\s{0,100}({file_name}[^=]{1,2000}?)\s{0,100}\w+=""",
    """"Domain":"({domain}[^"]{1,2000})""",
    """"Subject":"\s{0,100}({subject}[^",]{1,2000})\s{0,100}"""",
    """"MessageSize":({bytes}\d{1,100})""",
    """"Direction":"({direction}[^"]{1,2000})""",
    """"SenderAddress":"({sender}[^"]{1,2000})""",
    """"RecipientAddress":"({recipient}[^"]{1,2000})""",
    """"TransportRule":"({alert_name}[^"]{1,2000})""",
    """"EventType":"({alert_type}[^"]{1,2000})""",
    """Category\s{1,100}\[({category}[^\]]{1,2000})\]"""	
 ]
   DupFields=["sender->user_email"]


}
```