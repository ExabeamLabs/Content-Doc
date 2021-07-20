#### Parser Content
```Java
{
Name = cef-symantec-email-alert
    Vendor = Symantec
    Product = Symantec Email Security.cloud
    Lms = ArcSight
    DataType = "dlp-email-alert"
    TimeFormat = "epoch"
    Conditions = [ """CEF""", """|Symantec|Symantec Email Security.cloud|""" ]
    Fields = [
      """"logging_device_ip ":"({host}[^"]{1,2000})"""",
      """\Wrt=({time}\d{1,100})""",
      """"sender_ip":"({src_ip}[^"]{1,2000})"""",
      """"header_subject":"({subject}[^"]{1,2000})""",
      """"smtp_to":\[({recipients}"({recipient}[^"@]{1,2000}@({external_domain_recipient}[^"@]{1,2000})).*?)\]""",
      """\Wsuser=({sender}[^=@]{1,2000}@({external_domain_sender}[^\s]{1,2000}))""",
      """"size":"?({bytes}\d{1,100})""",
      """\Wsuser=({user_email}\S+)""",
      """"dkim":"({outcome}[^"]{1,2000})""",
      """"event_id":({alert_id}\d{1,100})""",
      """"severity_id":({alert_severity}\d{1,100})""",
      """"feature_name":"({alert_type}[^"]{1,2000})"""",
      """"threat":\{"name":"({alert_name}[^"]{1,2000})""",
      """"product_name":"({product_name}[^"]{1,2000})"""",
    ]
    DupFields = [ "recipient->external_address" ]
  }
```