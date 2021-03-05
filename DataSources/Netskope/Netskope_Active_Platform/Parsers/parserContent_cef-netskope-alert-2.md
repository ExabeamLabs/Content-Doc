#### Parser Content
```Java
{
Name = cef-netskope-alert-2
  Vendor = Netskope
  Product = Netskope Active Platform
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
    """msg=({additional_info}.+?)\s+\w+=""",
    """ext__malware_type_=({alert_name}.+?)\s+\w+=""",
    """ext__malware_name_=({malware_filename}.+?)\s\w+=""",
    """ext__quarantine_file_name_=({file_path}.+?)\s\w+=""",
    """ext__alert_type_=({alert_type}.+?)\s\w+=""",
    """dpriv=({alert_type}.+?)\s\w+=""",
    """ext_action=({outcome}.+?)\s\w+=""",
    """outcome=({outcome}.+?)\s+\w+=""",
    """ext_category=({category}.+?)\s+\w+=""",
    """ext_md5=({md5}.+?)\s+\w+=""",
    """ext_url=({malware_url}.+?)\s+\w+="""
    
  ]
}
```