#### Parser Content
```Java
{
Name = cef-netskope-alert-2
  Vendor = Netskope
  Product = Netskope Security Cloud
  Lms = Direct
  DataType = "alert"
  TimeFormat = "epoch_sec"
  Conditions = [ """CEF:""", """|Skyformation|""", """SkyFormation Cloud Apps Security""", """destinationServiceName=Netskope""" , """ext__malware_name"""]
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """"timestamp":({time}\d{1,100})""",
    """"user_id"{1,20}:"{1,20}(({user_email}[^@]+@[^"]+)|({user_id}[^"]+))"""",
    """"app":"({process}[^"]+)""",
    """"{1,20}malware_sev"{1,20}:"{1,20}({alert_severity}[^"]+)""",
    """"malware_id"{1,20}:"{1,20}({alert_id}[^"]+)""",
    """suser=(({user_email}[^@"\s]+@[^@"\s]+)|(({domain}[^"@\\\/\s]+)[\\\/]+)?({user}[^"@\\\/\s]+))""",
    """msg=({additional_info}[^=]+?)\s{1,100}\w+=""",
    """"malware_type"{1,20}:"{1,20}({alert_name}[^"]+)"""",
    """ext__malware_name_=({malware_filename}[^=]+?)\s\w+=""",
    """ext__quarantine_file_name_=({file_path}[^=]+?)\s\w+=""",
    """"alert_type"{1,20}:"{1,20}({alert_type}[^"]+)"""",
    """dpriv=({alert_type}[^=]+?)\s\w+=""",
    """outcome=({outcome}[^=]+?)\s{1,100}\w+=""",
    """ext_category=({category}[^=]+?)\s{1,100}\w+=""",
    """fileHash=({md5}[^=]+?)\s{1,100}\w+=""",
    """ext_url=({malware_url}[^=]+?)\s{1,100}\w+=""",
    """"file_path"{1,20}:"{1,20}({file_path_at}[^"]+)"""",
    """"q_shared_with"{1,20}:"{1,20}({shared_with_at}[^"]+)""""
  ]
}
```