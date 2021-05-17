#### Parser Content
```Java
{
Name = symantec-security-alert-1
  Vendor = Symantec
  Product = Symantec Email Security.cloud
  Lms = Direct
  DataType = "alert"
  TimeFormat = "epoch"
  Conditions = [ """"eventType": """", """"squrlClickerIp": """", """"squrlRecipient": """", """"severity": """", """"url": """" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"timestamp_ms":\s{0,100}({time}\d{1,100})""",
    """"squrlRecipient":\s{0,100}"({user_email}[^"\s@;,]{1,2000}@[^"\s@;,]{1,2000})""",
    """"url":\s{0,100}"({malware_url}[^"]{1,2000})"""",
    """"severity":\s{0,100}"({alert_severity}[^"]{1,2000})"""",
    """"action":\s{0,100}"({outcome}[^"]{1,2000})"""",
    """"squrlClickerIp":\s{0,100}"({dest_ip}[A-Fa-f:\d.]{1,2000})"""",
    """"eventType":\s{0,100}"({alert_name}[^"]{1,2000})"""",
  ]
  DupFields = [ "alert_name->alert_type" ]
}
```