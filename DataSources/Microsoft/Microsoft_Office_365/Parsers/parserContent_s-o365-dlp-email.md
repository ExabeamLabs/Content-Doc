#### Parser Content
```Java
{
Name = s-O365-dlp-email
  Vendor = Microsoft
  Product = Microsoft Office 365
  Lms = QRadar
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """"RecipientAddress"""", """"SenderAddress"""", """"MessageTraceId"""" ]
  Fields = [
    """exabeam_host=({host}[^\s]+)""",
    """"Received"{1,20}:\s{0,100}"{1,20}({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d{1,100})""",
    """"DateReceived":\s{0,100}"({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\dZ)""",
    """"RecipientAddress"{1,20}:\s{0,100}"{1,20}[^@]+@({external_domain_recipient}[^",]+)""",
    """"RecipientAddress"{1,20}:\s{0,100}"{1,20}({recipients}[^",]+)"""",
    """"RecipientAddress"{1,20}:\s{0,100}"{1,20}({recipient}[^"\s,;]+)""",
    """"SenderAddress"{1,20}:\s{0,100}"{1,20}(<>|\\+|({sender}[^">,]+))""",
    """"MessageId"{1,20}:\s{0,100}"{1,20}({message_id}[^",]+)"""",
    """"SenderAddress"{1,20}:\s{0,100}"{1,20}[^@]+@({external_domain_sender}[^",]+)""",
    """"ToIP"{1,20}:\s{0,100}"{1,20}?(?:null|({dest_ip}[a-fA-F\d.:]+))""",
    """"FromIP"{1,20}:\s{0,100}"{1,20}?(?:null|({src_ip}[a-fA-F\d.:]+))""",
    """"Subject"{1,20}:\s{0,100}(?:"{1,20}|"{1,20}({subject}.+?)\s{0,100})"{1,20}
```