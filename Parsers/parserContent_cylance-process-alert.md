#### Parser Content
```Java
{
Name = cylance-process-alert
  Vendor = BlackBerry
  Product = BlackBerry Protect
  Lms = Direct
  DataType = "process-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """Cylance Protect""", """MEMORY_VIOLATION""", """outcome=terminate""", """|security-threat-detected|""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """created":"({time}\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """"user_name":"({user}[^"]+)"""",
    """"process_id":({pid}\d+)""",
    """"image_name":"({process}({directory}(\w:)?(?:[^:\]]+)?[\\\/])?({process_name}[^\\\/"\]]+?))"""",
    """"file_hash_id":"({sha256_sum}[^"]+)"""",
    """"groups":"({user_group}[^"]+)"""",
    """"device_id":"({device_id}[^"]+)"""",
    """outcome=({outcome}terminate)""",
    """ Category \[({alert_name}[^\]]+)\]""",
    """msg=({alert_type}[^:]+)""",
    """"agent_event_id":"({alert_id}[^"]+)"""",
  ]
  DupFields = [ "directory->process_directory" ]
}
```