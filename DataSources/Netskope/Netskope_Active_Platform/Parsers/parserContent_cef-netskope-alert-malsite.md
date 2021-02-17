#### Parser Content
```Java
{
Name = cef-netskope-alert-malsite
  Vendor = Netskope
  Product = Netskope Active Platform
  Lms = Direct
  DataType = "alert"
  TimeFormat = "epoch_sec"
  Conditions = [ """CEF:""", """|Skyformation|""", """"alert_type":"malsite"""", """destinationServiceName=Netskope""", """|security-threat-detected|""" ]
  Fields = [
    """({host}[\w\-.]+)\s+Skyformation""",
    """"timestamp":({time}\d+)""",
    """"user":"(({user_email}[^@"\s]+@[^@"\s]+)|(({domain}[^"@\\\/\s]+)[\\\/]+)?({user}[^"@\\\/\s]+))"""",
    """"app":"({process}[^"]+)""",
    """"dstip":"({dest_ip}[A-Fa-f:\d.]+)""",
    """"srcip":"({src_ip}[A-Fa-f:\d.]+)""",
    """"malsite_category":\["({threat_category}[^"]+)"[^\]]*?\]""",
    """"alert_name":"({malware_url}[^"]+)""",
    """"alert_type":"({alert_type}[^"]+)""",
    """"action":"({outcome}[^"]+)""", 
    """"severity_level":"({alert_severity}[^"]+)""",
    """"hostname":"({src_host}[^"]+)""",
    """"referer":"({referrer}[^"]+)""",
    """"malsite_category":\["?({alert_name}[^\]]+?)"?\]""",
    """"url":"[^"]+?({top_domain}[^\/\.\s]+(?i)(\.(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+)"""
    """"browser":"({process}[^"]+)"""",  
  ]
  DupFields = ["top_domain->additional_info"]
}
```