#### Parser Content
```Java
{
Name = s-symantec-email-alert
  Vendor = Symantec
  Product = Symantec Email Security.cloud
  Lms = Splunk
  DataType = "dlp-email-alert"
  TimeFormat = "epoch_sec"
  Conditions = [ """"mailProcessingStartTime": """, """"isOutbound": """, """"envFrom": """, """"senderIp": """ ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """"mailProcessingStartTime":\s*({time}\d+)""",
    """"isOutbound":\s*({is_outbound}[^,]+)""",
    """"envFrom":\s*"({sender}[^"@]+@({external_domain_sender}[^"@]+))""",
    """"envTo":\s*\[({recipients}"({recipient}[^"@]+@({external_domain_recipient}[^"@]+))".*?)\]""",
    """"subject":\s*"\s*({subject}.+?)\s*"""",
    """"senderIp":\s*"*({src_ip}[a-fA-F\d.:]+)""",
    """"fileNameOrURL":\s*"({attachment}[^"]+)""",
    """"severity":\s*"({alert_severity}[^"]+)""",
    """"securityService":\s*"({alert_type}[^"]+)"""",
    """"action":\s*"({outcome}[^"]+)""",
    """"malwareName":\s*"(null|unknown|({alert_name}[^"]+))""",
    """"malwareCategory":\s*"({threat_category}[^"]+)""",
  ]
}
```