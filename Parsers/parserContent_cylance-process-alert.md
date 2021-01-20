#### Parser Content
```Java
{
Name = cylance-process-alert
  Vendor = Cylance PROTECT
  Product = Cylance PROTECT Memory Protection
  Lms = Direct
  DataType = "process-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """Cylance Protect""", """MEMORY_VIOLATION""", """outcome=terminate""", """|security-threat-detected|""" ]
  Fields = [
    """created":"({time}\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """"user_name":"({user}[^"]+)"""",
    """"process_id":({pid}\d+)""",
    """"image_name":"({process}({directory}(\w:)?(?:[^:\]]+)?[\\\/])?({process_name}[^\\\/"\]]+?))"""",
    """"file_hash_id":"({sha256_sum}[^"]+)"""",
    """"groups":"({user_group}[^"]+)"""",
    """({host}\S+)\s+Skyformation """,
    """"device_id":"({device_id}[^"]+)"""",
    """outcome=({outcome}terminate)""",
    """ Category \[({alert_name}[^\]]+)\]""",
    """ SubCategory \[({alert_type}[^\]]+)\]""",
    """"agent_event_id":"({alert_id}[^"]+)"""",
  ]
  DupFields = [ "directory->process_directory" ]
}
```