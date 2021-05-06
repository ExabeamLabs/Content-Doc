#### Parser Content
```Java
{
Name = cef-netskope-alert-malsite
  Vendor = Netskope
  Product = Netskope Security Cloud
  Lms = Direct
  DataType = "alert"
  TimeFormat = "epoch_sec"
  Conditions = [ """CEF:""", """|Skyformation|""", """"alert_type":"malsite"""", """destinationServiceName=Netskope""", """|security-threat-detected|""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """"timestamp":({time}\d+)""",
    """"user":"(({user_email}[^@"\s]+@[^@"\s]+)|(({domain}[^"@\\\/\s]+)[\\\/]+)?({user}[^"@\\\/\s]+))"""",
    """"app":"({process}[^"]+)""",
    """"dstip":"({dest_ip}[A-Fa-f:\d.]+)""",
    """"srcip":"({src_ip}[A-Fa-f:\d.]+)""",
    """"malsite_category":\["({alert_type}[^"]+)"[^\]]*?\]""",
    """"alert_name":"({malware_url}[^"]+)""",
    """dpriv=({alert_name}[^=]+)\s+\w+=""",
    """"alert_type":"({alert_name}[^"]+)""",
    """"action":"({outcome}[^"]+)""", 
    """"severity_level":"({alert_severity}[^"]+)""",
    """"hostname":"({src_host}[^"]+)""",
    """"referer":"({referrer}[^"]+)""",
    """"url":"(\w+\\*:\/+)?(((\d+\.){3}\d+[^\s"]+)|(www\.)?[^"\/]*?({top_domain}[0-9A-Za-z]{2,255}\.[0-9A-Za-z]{2,3}\.[0-9A-Za-z]{2,3}|[0-9A-Za-z]{2,255}\.[0-9A-Za-z]{2,3}))("|\/|\?)"""
    """"url":"([^"\/]*?)({top_domain}[^.\s\/:]+(?=(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+))("|\/)""",

    """"browser":"({process}[^"]+)"""",  
    """"site":"({site_at}[^",]+)"""",
    """"_id":"({alert_id}[^"]+)"""
  ]
  DupFields = ["top_domain->additional_info", "alert_type->threat_category"]
}
```