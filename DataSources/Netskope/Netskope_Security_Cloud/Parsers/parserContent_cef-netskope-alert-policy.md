#### Parser Content
```Java
{
Name = cef-netskope-alert-policy
  Conditions = [ """CEF:""", """|Skyformation|""", """"alert_type":"policy"""", """destinationServiceName=Netskope""", """|security-threat-detected|""", """"alert":"yes"""" ]
  Fields = ${NetskopeParserTemplates.cef-netskope-alert.Fields}[
    """"srcip":"({src_translated_ip}[A-Fa-f:\d.]+)""",
    """"malsite_category":\["({threat_category}[^"]+)"[^\]]*?\]""",
    """"alert_type":"({alert_type}[^"]+)""",
    """"action":"({outcome}[^"]+)""",
    """"hostname":"({src_host}[^"]+)""",
    """"referer":"({referrer}[^"]+)""",
    """"policy":"({additional_info}[^"]+)""",
    """"page":"({web_domain}[^\\\/"]+)""",
    """"app":"({process_name}[^"]+)"""",
    """CEF:([^\|]*\|){6}({alert_severity}[^\|]+)\|""",
    """"_id":"({alert_id}[^"]+)""",
    """"file_path":"({file_path_at}[^"]+)"""",
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
    """"timestamp":({time}\d+)""",
    """"user":"(({user_email}[^@"\s]+@[^@"\s]+)|(({domain}[^"@\\\/\s]+)[\\\/]+)?({user}[^"@\\\/\s]+))"""",
    """"dstip":"({dest_ip}[A-Fa-f:\d.]+)""",
    """"alert_name":"({alert_name}[^"]+)""",
    """"url":"({malware_url}[^"]+)""",
    """"userip":"({src_ip}[A-Fa-f:\d.]+)"""
  ]

```