#### Parser Content
```Java
{
Name = cef-O365-dlp-email-out
  Vendor = Microsoft
  Product = Office 365
  Lms = ArcSight
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """"Direction":"Outbound"""", """"MessageTraceId":"""", """"SenderAddress":"""", """"RecipientAddress":"""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[\w\-.]{1,2000})""",
    """"Date":"({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d)""",
    """"Subject":"({subject}[^"]{1,2000})"""",
    """"Direction":"({direction}[^"]{1,2000})"""",
    """"SenderAddress":"({sender}[^"]{1,2000})"""",
    """"RecipientAddress":"({external_address}[^"]{1,2000})"""",
    """"RecipientAddress":"({recipients}[^"]{1,2000})"""",
    """"MessageSize":"?({bytes}\d{1,100})""",
    """"EventType":"({alert_type}[^"]{1,2000})""""
  ]
  DupFields = [ "alert_type->alert_name", "alert_type->outcome", "sender->email_user" ]


}
```