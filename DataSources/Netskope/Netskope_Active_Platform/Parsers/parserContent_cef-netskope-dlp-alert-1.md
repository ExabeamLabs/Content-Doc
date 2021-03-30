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
cef-netskope-alert = {
  Vendor = Netskope
  Product = Netskope Active Platform
  Lms = Direct
  DataType = "alert"
  TimeFormat = "epoch_sec"
  Fields = [
    """({host}[\w\-.]+)\s+Skyformation""",
    """"timestamp":({time}\d+)""",
    """"user":"(({user_email}[^@"\s]+@[^@"\s]+)|(({domain}[^"@\\\/\s]+)[\\\/]+)?({user}[^"@\\\/\s]+))"""",
    """"dstip":"({dest_ip}[A-Fa-f:\d.]+)""",
    """"alert_name":"({alert_name}[^"]+)""",
    """"url":"({malware_url}[^"]+)""",
  ]

```