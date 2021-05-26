#### Parser Content
```Java
{
Name = cef-symantec-dlp-alert-1
    Vendor = Symantec
    Product = Symantec DLP
    Lms = ArcSight
    DataType = "dlp-alert"
    TimeFormat = "epoch"
    Conditions = [ """CEF""", """|Symantec|Symantec Data Loss Prevention|""" ]
    Fields = [
      """"collector_name":"({host}[^"]{1,2000})"""",
      """\Wrt=({time}\d{1,100})""",
      """"desc":"({additional_info}[^"]{1,2000})"""",
      """"sender_ip":"({src_ip}[^"]{1,2000})"""",
      """"recipient_ip":"({dest_ip}[^"]{1,2000})"""",
      """"recipient_identifier":"({target}[^"]{1,2000})"""",
      """"policy":\{.*?"name":"({alert_name}[^"]{1,2000})"""",
      """"feature_name":"({alert_type}[^"]{1,2000})"""",
      """"event_id":({alert_id}\d{1,100})""",
      """"severity_id":({alert_severity}\d{1,100})""",
      """"product_name":"({product_name}[^"]{1,2000})"""",
    ]
  }
```