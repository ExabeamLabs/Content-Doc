#### Parser Content
```Java
{
Name = cef-netskope-alert-1
  Vendor = Netskope
  Product = Netskope Security Cloud
  Lms = Direct
  DataType = "alert"
  TimeFormat = "epoch_sec"
  Conditions = [ """destinationServiceName =Netskope""", """"alert":"yes"""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """"_insertion_epoch_timestamp"{1,10}:({time}\d{1,100})""",
    """"timestamp":({time}\d{1,100})""",
    """"user":"(({user_email}[^@"\s]{1,2000}@[^@"\s]{1,2000})|(({domain}[^"@\\\/\s]{1,2000})[\\\/]{1,2000})?({user}[^"@\\\/\s]{1,2000}))"""",
    """duser=({external_address}[^@<]{1,2000}@?[^\s,>]{1,2000})""",
    """"app":"({process}[^"]{1,2000})""",
    """"type":"({alert_type}[^"]{1,2000})""",
    """"category":"(n\/a|({alert_type}[^"]{1,2000}))""",
    """"url":"({malware_url}[^"]{1,2000})""",
    """"severity":"({alert_severity}[^"]{1,2000})""",
    """"md5":"({md5}[^"]{1,2000})""",
    """"policy":"({alert_name}[^"]{1,2000})""",
    """"alert_name":"\s{0,100}({additional_info}[^"]{1,2000})"""",
    """"alert_type":"({alert_name}[^"]{1,2000})""",
    """dpriv=({alert_name}[^=]{1,2000})\s{1,100}\w+=""", 
    """"file_path":"({malware_file_name}[^"]{1,2000})""",
    """"object":"({object}[^"]{1,2000})""",
    """"breach_id":"\s{0,100}({alert_id}[^"]{1,2000})"""",
    """duser=({user}[^\s]{1,2000})""",
    """"organization_unit":"({user_ou}[^"]{1,2000})"""",
    """"shared_with":"({shared_with_at}[^"]{1,2000})"""",
    """"site":"({site_at}[^"]{1,2000})""""
  ]
  DupFields = [ "malware_url->full_url", "malware_file_name->file_path_at" ]


}
```