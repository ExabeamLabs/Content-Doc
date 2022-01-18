#### Parser Content
```Java
{
Name = cef-o365-dlp-email
  Vendor = Microsoft
  Product = Microsoft Office 365
  Lms = ArcSight
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """|security-threat-detected|""", """cat=security-alert""", """=Office 365""", """act=send-mail""", """"MessageTraceId":"""", """"EventType":"""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)\.\d{1,100}Z\s{1,100}[\w\-.]{1,2000}\s{1,100}Skyformation"""
    """filePath=<*({file_path}.+?)>*\s\w+=""",
    """fname=({file_name}.+?)\s{0,100}\w+=""",
    """"Domain":"({domain}[^"]{1,2000})""",
    """"Subject":"({subject}.+?)\s{0,100}"""",
    """"MessageSize":({bytes}\d{1,100})""",
    """"Direction":"({direction}[^"]{1,2000})""",
    """"SenderAddress":"({sender}[^"]{1,2000})""",
    """"SenderAddress":"[^@"]{1,2000}@({external_domain_sender}[^",]{1,2000})"""",
    """"RecipientAddress":"({recipient}[^"]{1,2000})""",
    """"RecipientAddress":"[^@"]{1,2000}@({external_domain_recipient}[^",]{1,2000})"""",
    """"TransportRule":"({alert_name}[^"]{1,2000})""",
    """"EventType":"({alert_type}[^"]{1,2000})"""
    	
 ]
   DupFields=["sender->user_email"]


}
```