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
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)\.\d{1,100}Z\s{1,100}[\w\-.]+\s{1,100}Skyformation"""
    """filePath=<*({file_path}.+?)>*\s\w+=""",
    """fname=({file_name}.+?)\s{0,100}\w+=""",
    """"Domain":"({domain}[^"]+)""",
    """"Subject":"({subject}.+?)\s{0,100}"""",
    """"MessageSize":({bytes}\d{1,100})""",
    """"Direction":"({direction}[^"]+)""",
    """"SenderAddress":"({sender}[^"]+)""",
    """"SenderAddress":"[^@"]+@({external_domain_sender}[^",]+)"""",
    """"RecipientAddress":"({recipient}[^"]+)""",
    """"RecipientAddress":"[^@"]+@({external_domain_recipient}[^",]+)"""",
    """"TransportRule":"({alert_name}[^"]+)""",
    """"EventType":"({alert_type}[^"]+)"""
    	
 ]
   DupFields=["sender->user_email"]
}
```