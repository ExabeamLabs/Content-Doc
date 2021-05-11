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
    """"mailProcessingStartTime":\s{0,100}({time}\d{1,100})""",
    """"isOutbound":\s{0,100}({is_outbound}[^,]+)""",
    """"envFrom":\s{0,100}"({sender}[^"@]+@({external_domain_sender}[^"@]+))""",
    """"envTo":\s{0,100}\[({recipients}"({recipient}[^"@]+@({external_domain_recipient}[^"@]+))".*?)\]""",
    """"subject":\s{0,100}"\s{0,100}({subject}.+?)\s{0,100}"""",
    """"senderIp":\s{0,100}"{0,20}({src_ip}[a-fA-F\d.:]+)""",
    """"fileNameOrURL":\s{0,100}"({attachment}[^"]+)""",
    """"severity":\s{0,100}"({alert_severity}[^"]+)""",
    """"securityService":\s{0,100}"({alert_type}[^"]+)"""",
    """"action":\s{0,100}"({outcome}[^"]+)""",
    """"malwareName":\s{0,100}"(null|unknown|({alert_name}[^"]+))""",
    """"malwareCategory":\s{0,100}"({threat_category}[^"]+)""",
    """"messageSize":\s{0,100}({bytes}\d{1,100})""",
  ]
}
```