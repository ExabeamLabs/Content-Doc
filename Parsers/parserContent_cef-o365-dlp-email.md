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
    """cs6=.*?"Date":"({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d)""",
    """cs6=.*?"Subject":"({subject}[^"]+)"""",
    """cs6=.*?"Direction":"({direction}[^"]+)"""",
    """cs6=.*?"SenderAddress":"({sender}[^",]+)"""",
    """cs6=.*?"SenderAddress":"({external_address}[^",]+)"""",
    """cs6=.*?"SenderAddress":"[^@]+@({external_domain}[^",]+)"""",
    """cs6=.*?"RecipientAddress":"({recipients}[^"]+)"""",
    """cs6=.*?"MessageSize":"?({bytes}\d+)""",
    """cs6=.*?"EventType":"({alert_type}[^"]+)""""
  ]
  DupFields = [ "alert_type->alert_name", "alert_type->outcome" ]
}
```