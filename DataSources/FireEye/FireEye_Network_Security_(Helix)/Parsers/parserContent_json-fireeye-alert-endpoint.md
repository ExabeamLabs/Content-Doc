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
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """"created_at":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
    """"iocnames":"({alert_name}[^"]{1,2000})""",
    """"description":"({additional_info}[^"]{1,2000})""",
    """virus.+?"description":"({alert_name}[^"]{1,2000})""",
    """"severity":"({alert_severity}[^"]{1,2000})""",
    """"threat_type":({alert_type}\d{1,100})""",
    """"source":"({dest_host}[^"]{1,2000})""",
    """"destination":"({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """details.+?"username":"([\w\s]{1,2000}\\+)?(system|({user}[^"]{1,2000}))""",
    """"process":"({process_name}[^"]{1,2000})"""
    """"args":"({process}.*)","pid""",
    """"virus":"({malware_name}[^"]{1,2000})"""
    """"result":"({outcome}[^"]{1,2000})""",
    """"filepath":"({file_path}({file_parent}.*?)({file_name}[^\\\."]{1,2000}(\.({file_ext}[^\\\."]{1,2000}))?))""""
    """"file_name":"({file_path}({file_parent}.*?)({file_name}[^\\\."]{1,2000}(\.({file_ext}[^\\\."]{1,2000}))?))"""",
    """"file_name":"({file_name}[^\\\."]{1,2000}(\.({file_ext}[^\\\."]{1,2000}))?)""""
  ]
}
```