#### Parser Content
```Java
{
Name = cef-O365-dlp-email-in
  Vendor = Microsoft
  Product = Office 365
  Lms = ArcSight
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """"Direction":"Inbound"""", """"MessageTraceId":"""", """"SenderAddress":""", """"RecipientAddress":"""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}[\w\-.]+)""",
    """"Date":"({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d)""",
    """"Subject":"({subject}[^"]+)"""",
    """"Direction":"({direction}[^"]+)"""",
    """"SenderAddress":"({sender}[^",]+)"""",
    """"SenderAddress":"[^@]+@({external_domain}[^",]+)"""",
    """"RecipientAddress":"({recipients}[^"]+)"""",
    """"MessageSize":"?({bytes}\d+)""",
    """"EventType":"({alert_type}[^"]+)""""
  ]
  DupFields = [ "alert_type->alert_name", "alert_type->outcome", "sender->external_address" ]
}
```