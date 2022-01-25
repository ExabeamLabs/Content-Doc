#### Parser Content
```Java
{
Name = cef-netskope-alert-2
  Vendor = Netskope
  Product = Netskope Security Cloud
  Lms = Direct
  DataType = "alert"
  TimeFormat = "epoch_sec"
  Conditions = [ """destinationServiceName =Netskope""" , """"malware_type""""]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"timestamp":({time}\d{1,100})""",
    """"user_id"{1,20}:"{1,20}(({user_email}[^@]{1,2000}@[^"]{1,2000})|({user_id}[^"]{1,2000}))"""",
    """"app":"({process}[^"]{1,2000})""",
    """"{1,20}malware_sev"{1,20}:"{1,20}({alert_severity}[^"]{1,2000})""",
    """"malware_id"{1,20}:"{1,20}({alert_id}[^"]{1,2000})""",
    """suser=(({user_email}[^@"\s]{1,2000}@[^@"\s]{1,2000})|(({domain}[^"@\\\/\s]{1,2000})[\\\/]{1,2000})?({user}[^"@\\\/\s]{1,2000}))""",
    """msg=({additional_info}[^=]{1,2000}?)\s{1,100}\w+=""",
    """"malware_type"{1,20}:"{1,20}({alert_name}[^"]{1,2000})"""",
    """ext__malware_name_=({malware_filename}[^=]{1,2000}?)\s\w+=""",
    """ext__quarantine_file_name_=({file_path}[^=]{1,2000}?)\s\w+=""",
    """"alert_type"{1,20}:"{1,20}({alert_type}[^"]{1,2000})"""",
    """dpriv=({alert_type}[^=]{1,2000}?)\s\w+=""",
    """outcome=({outcome}[^=]{1,2000}?)\s{1,100}\w+=""",
    """ext_category=({category}[^=]{1,2000}?)\s{1,100}\w+=""",
    """fileHash=({md5}[^=]{1,2000}?)\s{1,100}\w+=""",
    """ext_url=({malware_url}[^=]{1,2000}?)\s{1,100}\w+=""",
    """"file_path"{1,20}:"{1,20}({file_path_at}[^"]{1,2000})"""",
    """"q_shared_with"{1,20}:"{1,20}({shared_with_at}[^"]{1,2000})""""
  ]


}
```