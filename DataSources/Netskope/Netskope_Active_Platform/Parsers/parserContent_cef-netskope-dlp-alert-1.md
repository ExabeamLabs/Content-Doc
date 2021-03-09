#### Parser Content
```Java
{
Name = cef-netskope-dlp-alert-1
  Conditions = [ """CEF:""", """|Skyformation|""", """"alert_type":"DLP"""", """destinationServiceName=Netskope""", """"alert_name":""""  ]
  Fields = ${NetskopeParserTemplates.cef-netskope-alert.Fields}[
    """"app":"({app}[^"]+)""",
    """"_id":"({alert_id}[^"]+)""",
    """"category":"({threat_category}[^"]+)""",
    """"md5":"({md5}[^"\s]+)"""",
    """"dlp_rule_severity":"({alert_severity}[^"]+)""",
    """"alert_type":"({alert_type}[^"]+)""",
    """"policy":"({additional_info}[^"]+)""",
    """"action":"({outcome}[^"]+)""",
    """"*hostname"*:"*({src_host}[^"]+)"""",
    """"owner":"({file_owner_at}[^"]+)"""",
    """"from_user":"({from_user_at}[^"]+)"""",
    """"dlp_file":"({file_path_at}[^"]+)"""",
    """"shared_with":"("shared_with_at}[^"]+)"""",
    """"sha256":"({sha256_at}[^"]+)"""",
    """"site":"({site_at}[^"]+)""""
  ]
}
```