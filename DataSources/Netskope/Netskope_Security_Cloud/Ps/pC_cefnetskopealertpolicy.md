#### Parser Content
```Java
{
Name = cef-netskope-alert-policy
  Conditions = [ """CEF:""", """|Skyformation|""", """"alert_type":"policy"""", """destinationServiceName=Netskope""", """|security-threat-detected|""", """"alert":"yes"""" ]
  Fields = ${NetskopeParserTemplates.cef-netskope-alert.Fields}[
    """"srcip":"({src_translated_ip}[A-Fa-f:\d.]{1,2000})""",
    """"malsite_category":\["({threat_category}[^"]{1,2000})"[^\]]{0,2000}?\]""",
    """"alert_type":"({alert_type}[^"]{1,2000})""",
    """"action":"({outcome}[^"]{1,2000})""",
    """"hostname":"({src_host}[^"]{1,2000})""",
    """"referer":"({referrer}[^"]{1,2000})""",
    """"policy":"({additional_info}[^"]{1,2000})""",
    """"page":"({web_domain}[^\\\/"]{1,2000})""",
    """CEF:([^\|]{0,2000}\|){6}({alert_severity}[^\|]{1,2000})\|""",
    """"_id":"({alert_id}[^"]{1,2000})""",
    """"file_path":"({file_path_at}[^"]{1,2000})"""",
    """"site":"({site_at}[^"]{1,2000})""""
  ]
}
cef-netskope-alert = {
  Vendor = Netskope
  Product = Netskope Security Cloud
  Lms = Direct
  DataType = "alert"
  TimeFormat = "epoch_sec"
  Fields = [
    """"hostname":"({host}[^",]{1,2000})"""",
    """"timestamp":({time}\d{1,100})""",
    """"user":"(({user_email}[^@"\s]{1,2000}@[^@"\s]{1,2000})|(({domain}[^"@\\\/\s]{1,2000})[\\\/]{1,2000})?({user}[^"@\\\/\s]{1,2000}))"""",
    """"dstip":"({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """"alert_name":"({alert_name}[^"]{1,2000})""",
    """"url":"({malware_url}[^"]{1,2000})""",
    """"userip":"({src_ip}[A-Fa-f:\d.]{1,2000})"""
  ]

```