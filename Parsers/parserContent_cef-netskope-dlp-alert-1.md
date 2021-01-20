#### Parser Content
```Java
{
Name = cef-netskope-dlp-alert-1
  Conditions = [ """CEF:""", """|Skyformation|""", """"alert_type":"DLP"""", """destinationServiceName=Netskope""", """"alert_name":""""  ]
  Fields = ${NetskopeParserTemplates.cef-netskope-alert.Fields}[
    """"app":"({app}[^"]+)""",
    """"malware_id":"({alert_id}[^"]+)""",
    """"category":"({threat_category}[^"]+)""",
    """"md5":"({md5}[^"\s]+)"""",
    """"dlp_rule_severity":"({alert_severity}[^"]+)""",
    """"alert_type":"({alert_type}[^"]+)""",
    """"policy":"({additional_info}[^"]+)""",
    """"action":"({outcome}[^"]+)""",
    """"*hostname"*:"*({src_host}[^"]+)""""
  ]
}
```