#### Parser Content
```Java
{
Name = cef-O365-dlp-email
  Vendor = Microsoft
  Product = Office 365
  Lms = ArcSight
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """"MessageTraceId":"""", """"SenderAddress":"""", """"RecipientAddress":"""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}[\w\-.]+)""",
    """({host}[\w\-.]+) Skyformation""",
    """cs6=.*?"StartDate":"({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d)""",
    """cs6=.*?"Subject":"({subject}.+?)\s*",""",
    """cs6=.*?"Direction":"({direction}[^"]+)"""",
    """cs6=.*?"SenderAddress":"({sender}[^",]+)"""",
    """cs6=.*?"SenderAddress":"[^@]+@({external_domain_sender}[^",]+)"""",
    """cs6=.*?"RecipientAddress":"[^@]+@({external_domain_recipient}[^",]+)"""",
    """cs6=.*?"RecipientAddress":"({recipients}[^"]+)"""",
    """cs6=.*?"RecipientAddress":"({recipient}[^"\s,;]+)""",
    """cs6=.*?"Size":"?({bytes}\d+)""",
    """cs6=.*?"Status":"({outcome}[^"]+)"""",
    """cs6=.*?"ToIP":"?(?:null|({dest_ip}[a-fA-F\d.:]+))""",
    """cs6=.*?"FromIP":"?(?:null|({src_ip}[a-fA-F\d.:]+))""",
    """cs6=.*?"EventType":"({alert_type}[^"]+)"""",
    """cs6=.*?"MessageTraceId":"({message_id}[^"]+)"""",
  ]
  DupFields = [ "alert_type->alert_name" ]
}
```