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
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """"timestamp_ms":\s*({time}\d+)""",
    """"squrlRecipient":\s*"({user_email}[^"\s@;,]+@[^"\s@;,]+)""",
    """"url":\s*"({malware_url}[^"]+)"""",
    """"severity":\s*"({alert_severity}[^"]+)"""",
    """"action":\s*"({outcome}[^"]+)"""",
    """"squrlClickerIp":\s*"({dest_ip}[A-Fa-f:\d.]+)"""",
    """"eventType":\s*"({alert_name}[^"]+)"""",
  ]
  DupFields = [ "alert_name->alert_type" ]
}
```