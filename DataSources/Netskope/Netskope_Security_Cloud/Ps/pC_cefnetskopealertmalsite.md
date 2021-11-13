#### Parser Content
```Java
{
Name = cef-netskope-alert-malsite
  Vendor = Netskope
  Product = Netskope Security Cloud
  Lms = Direct
  DataType = "alert"
  TimeFormat = "epoch_sec"
  Conditions = [ """"alert_type":"malsite"""", """destinationServiceName =Netskope""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """"timestamp":({time}\d{1,100})""",
    """"user":"(({user_email}[^@"\s]{1,2000}@[^@"\s]{1,2000})|(({domain}[^"@\\\/\s]{1,2000})[\\\/]{1,2000})?({user}[^"@\\\/\s]{1,2000}))"""",
    """"app":"({process}[^"]{1,2000})""",
    """"dstip":"({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """"srcip":"({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """"malsite_category":\["({alert_type}[^"]{1,2000})"[^\]]{0,2000}?\]""",
    """"alert_name":"({malware_url}[^"]{1,2000})""",
    """dpriv=({alert_name}[^=]{1,2000})\s{1,100}\w+=""",
    """"alert_type":"({alert_name}[^"]{1,2000})""",
    """"action":"({outcome}[^"]{1,2000})""", 
    """"severity_level":"({alert_severity}[^"]{1,2000})""",
    """"hostname":"({src_host}[^"]{1,2000})""",
    """"referer":"({referrer}[^"]{1,2000})""",
    """"url":"({full_url}(\w+:\/+)?({web_domain}[^\\\/]{1,2000})[^"]{1,2000})""",
    """"browser":"({process}[^"]{1,2000})"""",  
    """"site":"({site_at}[^",]{1,2000})"""",
    """"_id":"({alert_id}[^"]{1,2000})"""
  ]
  DupFields = ["alert_type->threat_category"]


}
```