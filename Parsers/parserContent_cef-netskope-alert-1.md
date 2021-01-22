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
    """exabeam_host=({host}[\w.\-]+)""",
    """"_insertion_epoch_timestamp"":({time}\d+)""",
    """"timestamp":({time}\d+)""",
    """"user":"(({user_email}[^@"\s]+@[^@"\s]+)|(({domain}[^"@\\\/\s]+)[\\\/]+)?({user}[^"@\\\/\s]+))"""",
    """duser=({external_address}[^@<]+@?({external_domain}[^\s,>]+))""",
    """"app":"({process}[^"]+)""",
    """"type":"({alert_type}[^"]+)""",
    """"category":"(n\/a|({alert_type}[^"]+))""",
    """"url":"({malware_url}[^"]+)""",
    """"severity":"({alert_severity}[^"]+)""",
    """"md5":"({md5}[^"]+)""",
    """"policy":"({alert_name}[^"]+)""",
    """"alert_name":"\s*({additional_info}[^"]+)"""",
    """"alert_type":"({alert_name}[^"]+)""",
    """dpriv=({alert_name}[^=]+)\s+\w+=""", 
    """"file_path":"({malware_file_name}[^"]+)""",
    """"object":"({object}[^"]+)""",
    """"breach_id":"\s*({alert_id}[^"]+)"""",
    """duser=({user}[^\s]+)""",
    """"organization_unit":"({user_ou}[^"]+)""""
  ]
  DupFields = [ "malware_url->full_url" ]
}
```