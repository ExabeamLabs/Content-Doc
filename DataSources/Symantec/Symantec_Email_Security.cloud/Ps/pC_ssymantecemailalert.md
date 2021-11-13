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
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """"mailProcessingStartTime":\s{0,100}({time}\d{1,100})""",
    """"isOutbound":\s{0,100}({is_outbound}[^,]{1,2000})""",
    """"envFrom":\s{0,100}"({sender}[^"@]{1,2000}@[^"@]{1,2000})""",
    """"envTo":\s{0,100}\[({recipients}"({recipient}[^"@]{1,2000}@[^"@]{1,2000})".*?)\]""",
    """"subject":\s{0,100}"\s{0,100}({subject}.+?)\s{0,100}"""",
    """"senderIp":\s{0,100}"{0,20}({src_ip}[a-fA-F\d.:]{1,2000})""",
    """"fileNameOrURL":\s{0,100}"({attachment}[^"]{1,2000})""",
    """"severity":\s{0,100}"({alert_severity}[^"]{1,2000})""",
    """"securityService":\s{0,100}"({alert_type}[^"]{1,2000})"""",
    """"action":\s{0,100}"({outcome}[^"]{1,2000})""",
    """"malwareName":\s{0,100}"(null|unknown|({alert_name}[^"]{1,2000}))""",
    """"malwareCategory":\s{0,100}"({threat_category}[^"]{1,2000})""",
    """"messageSize":\s{0,100}({bytes}\d{1,100})""",
  ]


}
```