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
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """"timestamp":({time}\d+)""",
    """"user_id"+:"+(({user_email}[^@]+@[^"]+)|({user_id}[^"]+))"""",
    """"app":"({process}[^"]+)""",
    """"+malware_sev"+:"+({alert_severity}[^"]+)""",
    """"malware_id"+:"+({alert_id}[^"]+)""",
    """suser=(({user_email}[^@"\s]+@[^@"\s]+)|(({domain}[^"@\\\/\s]+)[\\\/]+)?({user}[^"@\\\/\s]+))""",
    """msg=({additional_info}[^=]+?)\s+\w+=""",
    """"malware_type"+:"+({alert_name}[^"]+)"""",
    """ext__malware_name_=({malware_filename}[^=]+?)\s\w+=""",
    """ext__quarantine_file_name_=({file_path}[^=]+?)\s\w+=""",
    """"alert_type"+:"+({alert_type}[^"]+)"""",
    """dpriv=({alert_type}[^=]+?)\s\w+=""",
    """outcome=({outcome}[^=]+?)\s+\w+=""",
    """ext_category=({category}[^=]+?)\s+\w+=""",
    """fileHash=({md5}[^=]+?)\s+\w+=""",
    """ext_url=({malware_url}[^=]+?)\s+\w+=""",
    """"file_path"+:"+({file_path_at}[^"]+)"""",
    """"q_shared_with"+:"+({shared_with_at}[^"]+)""""
  ]
}
```