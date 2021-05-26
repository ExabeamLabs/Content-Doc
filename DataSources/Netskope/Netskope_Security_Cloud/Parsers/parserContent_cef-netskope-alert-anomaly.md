#### Parser Content
```Java
{
Name = cef-netskope-alert-anomaly
  Vendor = Netskope
  Product = Netskope Security Cloud
  Lms = Direct
  DataType = "alert"
  TimeFormat = "epoch_sec"
  Conditions = [ """CEF:""", """|Skyformation|""", """"alert_type":"anomaly"""", """destinationServiceName=Netskope""", """|security-threat-detected|""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"timestamp":({time}\d{1,100})""",
    """"user":"(({user_email}[^@"\s]{1,2000}@[^@"\s]{1,2000})|(({domain}[^"@\\\/\s]{1,2000})[\\\/]{1,2000})?({user}[^"@\\\/\s]{1,2000}))"""",
    """"app":"({process}[^"]{1,2000})""",
    """"dstip":"({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """"srcip":"({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """"_id":"({alert_id}[^"]{1,2000})""",
    """"category":"({threat_category}[^"]{1,2000})""",
    """"alert_name":"({alert_name}[^"]{1,2000})""",
    """"alert_type":"({alert_type}[^"]{1,2000})""",
    """"url":"({malware_url}[^"]{1,2000})""",
    """"risk_level":"({alert_severity}[^"]{1,2000})""",
    """"hostname":"({src_host}[^"]{1,2000})""",
    """"site":"({site_at}[^",]{1,2000})""""
  ]
  DupFields = ["process->process_name","site_at->app"]
}
```