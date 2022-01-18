#### Parser Content
```Java
{
Name = cef-netskope-alert-malsite
  Vendor = Netskope
  Product = Netskope Security Cloud
  Lms = Direct
  DataType = "alert"
  TimeFormat = "epoch_sec"
  Conditions = [ """CEF:""", """|Skyformation|""", """"alert_type":"malsite"""", """destinationServiceName =Netskope""", """|security-threat-detected|""" ]
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
    """"url":"(\w+\\*:\/+)?(((\d{1,100}\.){3}\d{1,100}[^\s"]{1,2000})|(www\.)?[^"\/]{0,2000}?({top_domain}[0-9A-Za-z]{2,255}\.[0-9A-Za-z]{2,3}\.[0-9A-Za-z]{2,3}|[0-9A-Za-z]{2,255}\.[0-9A-Za-z]{2,3}))("|\/|\?)"""
    """"url":"([^"\/]{0,2000}?)({top_domain}[^.\s\/:]{1,2000}(?=(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+))("|\/)""",

    """"browser":"({process}[^"]{1,2000})"""",  
    """"site":"({site_at}[^",]{1,2000})"""",
    """"_id":"({alert_id}[^"]{1,2000})"""
  ]
  DupFields = ["top_domain->additional_info", "alert_type->threat_category"]


}
```