#### Parser Content
```Java
{
Name = symantec-process-created
  Vendor = Symantec
  Product = Symantec EDR
  Lms = Syslog
  DataType = "process-created"
  TimeFormat = "epoch"
  Conditions = [ """"event_id":8001001""", """"type_id":8001""", """"Symantec Endpoint Detection and Response"""", """collector_device_ip""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}?@\s{0,100})?({host}[\w.-]{1,2000})""",
    """"(start_)?time":({time}\d{1,100})""",
    """collector_device_name":"({host}[^"]{1,2000})"""",
    """"path":"({process}({process_directory}(?:[^";]{1,2000})?[\\\/;])?({process_name}[^\\\/";]{1,2000}?))"""",
    """user_name":"((?i)(LOCAL SERVICE|SYSTEM|NETWORK SERVICE)|({user}[^"]{1,2000}))"""",
    """user_domain":"(NT AUTHORITY|({domain}[^"]{1,2000}))"""",
    """"device_name":"({src_host}[^"]{1,2000})"""",
    """"message":"({additional_info}[^"]{1,2000})"""",
    """device_ip":"({src_ip}[a-fA-F\d:.]{1,2000})"""",
    """src_ip":"({src_ip}[a-fA-F\d:.]{1,2000})""""
    """src_port":({src_port}\d{1,100})""",
    """dst_port":({dest_port}\d{1,100})""",
    """dst_ip":"({dest_ip}[a-fA-F\d:.]{1,2000})"""",
    """md5":"({md5}[^"]{1,2000})"""",
    """event_id":({event_code}\d{1,2000})""",
    """size":({file_size}\d{1,100})""",
    """cmd_line":"({command_line}[^\n]{1,2000}?)\s{0,100}","""
  ]


}
```