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
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """"timestamp_ms":\s{0,100}({time}\d{1,100})""",
    """"squrlRecipient":\s{0,100}"({user_email}[^"\s@;,]+@[^"\s@;,]+)""",
    """"url":\s{0,100}"({malware_url}[^"]+)"""",
    """"severity":\s{0,100}"({alert_severity}[^"]+)"""",
    """"action":\s{0,100}"({outcome}[^"]+)"""",
    """"squrlClickerIp":\s{0,100}"({dest_ip}[A-Fa-f:\d.]+)"""",
    """"eventType":\s{0,100}"({alert_name}[^"]+)"""",
  ]
  DupFields = [ "alert_name->alert_type" ]
}
```