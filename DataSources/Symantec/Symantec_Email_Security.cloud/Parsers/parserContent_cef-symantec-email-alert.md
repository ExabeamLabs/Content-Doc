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
      """"logging_device_ip ":"({host}[^"]+)"""",
      """\Wrt=({time}\d+)""",
      """"sender_ip":"({src_ip}[^"]+)"""",
      """"header_subject":"({subject}[^"]+)""",
      """"smtp_to":\[({recipients}"({recipient}[^"@]+@({external_domain_recipient}[^"@]+)).*?)\]""",
      """\Wsuser=({sender}[^=@]+@({external_domain_sender}[^\s]+))""",
      """"size":"?({bytes}\d+)""",
      """\Wsuser=({user_email}\S+)""",
      """"dkim":"({outcome}[^"]+)""",
      """"event_id":({alert_id}\d+)""",
      """"severity_id":({alert_severity}\d+)""",
      """"feature_name":"({alert_type}[^"]+)"""",
      """"threat":\{"name":"({alert_name}[^"]+)""",
      """"product_name":"({product}[^"]+)"""",
    ]
    DupFields = [ "recipient->external_address" ]
  }
```