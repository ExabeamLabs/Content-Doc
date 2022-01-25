#### Parser Content
```Java
{
Name = json-o365-dlp-email
  Vendor = Microsoft
  Product = Office 365
  Lms = ArcSight
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """"MessageTraceId":"""", """"SenderAddress":"""", """"RecipientAddress":"""", """"Subject":""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[\w\-.]{1,2000})""",
    """"StartDate":"({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d)""",
    """"Subject":"\s{0,100}({subject}[^"]{1,2000}?)\s{0,100}",""",
    """"Direction":"({direction}[^"]{1,2000})"""",
    """"SenderAddress":"({sender}[^",]{1,2000})"""",
    """"SenderAddress":"[^@]{1,2000}@({external_domain_sender}[^",]{1,2000})"""",
    """"RecipientAddress":"[^@]{1,2000}@({external_domain_recipient}[^",]{1,2000})"""",
    """"RecipientAddress":"({recipients}[^"]{1,2000})"""",
    """"RecipientAddress":"({recipient}[^"\s,;]{1,2000})""",
    """"Size":"?({bytes}\d{1,100})""",
    """"Status":"({outcome}[^"]{1,2000})"""",
    """"ToIP":"?(?:null|({dest_ip}[a-fA-F\d.:]{1,2000}))""",
    """"FromIP":"?(?:null|({src_ip}[a-fA-F\d.:]{1,2000}))""",
    """"EventType":"({alert_type}[^"]{1,2000})"""",
    """"MessageTraceId":"({message_id}[^"]{1,2000})"""",
    """"triggered-by":\{"user-email":"({user_email}[^",]{1,2000})"""",
    """Category\s{1,100}\[({category}[^\]]{1,2000})\]"""
  ]
  DupFields = [ "alert_type->alert_name" ]


}
```