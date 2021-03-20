#### Parser Content
```Java
{
Name = json-fireeye-alert-endpoint
  Vendor = FireEye
  Product = FireEye Network Security (Helix)
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
  Conditions = [ """"type":"fireeye_rule"""", """"threat_type":""", """"category":"Host"""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """"created_at":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z)""",
    """"iocnames":"({alert_name}[^"]+)""",
    """"description":"({additional_info}[^"]+)""",
    """virus.+?"description":"({alert_name}[^"]+)""",
    """"severity":"({alert_severity}[^"]+)""",
    """"threat_type":({alert_type}\d+)""",
    """"source":"({dest_host}[^"]+)""",
    """"destination":"({dest_ip}[a-fA-F\d.:]+)""",
    """details.+?"username":"([\w\s]+\\+)?(system|({user}[^"]+))""",
    """"process":"({process_name}[^"]+)"""
    """"args":"({process}.*)","pid""",
    """"virus":"({malware_name}[^"]+)"""
    """"result":"({outcome}[^"]+)""",
    """"filepath":"({file_path}({file_parent}.*?)({file_name}[^\\\."]+(\.({file_ext}[^\\\."]+))?))""""
    """"file_name":"({file_path}({file_parent}.*?)({file_name}[^\\\."]+(\.({file_ext}[^\\\."]+))?))"""",
    """"file_name":"({file_name}[^\\\."]+(\.({file_ext}[^\\\."]+))?)""""
  ]
}
```