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
    """"{0,20}hostname"{0,20}:"{0,20}({src_host}[^"]+)"""",
    """"from_user":"({from_user_at}[^"]+)"""",
    """"shared_with":"("shared_with_at}[^"]+)"""",
    """"sha256":"({sha256_at}[^"]+)"""",
    """"site":"({site_at}[^"]+)""""
  ]
}
cef-netskope-alert = {
  Vendor = Netskope
  Product = Netskope Security Cloud
  Lms = Direct
  DataType = "alert"
  TimeFormat = "epoch_sec"
  Fields = [
    """"hostname":"({host}[^",]+)"""",
    """"timestamp":({time}\d{1,100})""",
    """"user":"(({user_email}[^@"\s]+@[^@"\s]+)|(({domain}[^"@\\\/\s]+)[\\\/]+)?({user}[^"@\\\/\s]+))"""",
    """"dstip":"({dest_ip}[A-Fa-f:\d.]+)""",
    """"alert_name":"({alert_name}[^"]+)""",
    """"url":"({malware_url}[^"]+)""",
    """"userip":"({src_ip}[A-Fa-f:\d.]+)"""
  ]

```