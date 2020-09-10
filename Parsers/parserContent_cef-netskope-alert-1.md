#### Parser Content
```Java
{
Name = cef-netskope-alert-1
  Vendor = Netskope
  Product = Netskope Active Platform
  Lms = Direct
  DataType = "alert"
  TimeFormat = "epoch_sec"
  Conditions = [ """CEF:""", """|Skyformation|""", """destinationServiceName=Netskope""", """"alert":"yes"""" ]
  Fields = [
    """({host}[\w\-.]+)\s+Skyformation""",
    """"_insertion_epoch_timestamp"":({time}\d+)""",
    """"timestamp":({time}\d+)""",
    """"user":"(({user_email}[^@"\s]+@[^@"\s]+)|(({domain}[^"@\\\/\s]+)[\\\/]+)?({user}[^"@\\\/\s]+))"""",
    """"app":"({process}[^"]+)""",
    """"type":"({threat_category}[^"]+)""",
    """"category":"(n\/a|({threat_category}[^"]+))""",
    """"url":"({malware_url}[^"]+)""",
    """"severity":"({alert_severity}[^"]+)""",
    """"md5":"({md5}[^"]+)""",
    """"policy":"({alert_name}[^"]+)""",
    """"alert_name":"\s*({alert_name}[^"]+)"""",
    """"type":"({alert_type}[^"]+)""",
    """dpriv=({alert_type}.*?)\s+\w+=""",    
    """"file_path":"({malware_file_name}[^"]+)""",
    """"object":"({object}[^"]+)""",
    """"breach_id":"\s*({alert_id}[^"]+)"""",
    """duser=({user}[^\s]+)""",
    """"organization_unit":"({user_ou}[^"]+)""""
  ]
  DupFields = [ "malware_url->full_url" ]
}
```